/* $Id */

/*
 ** Copyright (C) 2011-2011 Sourcefire, Inc.
 **
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License Version 2 as
 ** published by the Free Software Foundation.  You may not use, modify or
 ** distribute this program under any other version of the GNU General
 ** Public License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


/*
 * Reputation preprocessor
 *
 * This is the main entry point for this preprocessor
 *
 * Author: Hui Cao
 * Date: 06-01-2011
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  /* HAVE_CONFIG_H */
#include "sf_types.h"
#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_plugin_api.h"
#include "snort_debug.h"

#include "preprocids.h"
#include "spp_reputation.h"
#include "reputation_config.h"
#include "reputation_utils.h"

#include  <assert.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#ifndef WIN32
#include <strings.h>
#include <sys/time.h>
#endif
#include <stdlib.h>
#include <ctype.h>

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats reputationPerfStats;
#endif


const int MAJOR_VERSION = 1;
const int MINOR_VERSION = 1;
const int BUILD_VERSION = 1;

#ifdef SUP_IP6
const char *PREPROC_NAME = "SF_REPUTATION (IPV6)";
#else
const char *PREPROC_NAME = "SF_REPUTATION";
#endif

#define SetupReputation DYNAMIC_PREPROC_SETUP


/*
 * Function prototype(s)
 */
static void ReputationInit( char* );
static void ReputationCheckConfig(void);
static inline void ReputationProcess(SFSnortPacket *);
static void ReputationMain( void*, void* );
static void ReputationFreeConfig(tSfPolicyUserContextId);
static void ReputationPrintStats(int);
static void ReputationCleanExit(int, void *);

/********************************************************************
 * Global variables
 ********************************************************************/
int totalNumEntries = 0;
Reputation_Stats reputation_stats;
ReputationConfig *reputation_eval_config;
tSfPolicyUserContextId reputation_config;

#ifdef SNORT_RELOAD
static tSfPolicyUserContextId reputation_swap_config = NULL;
static void ReputationReload(char *);
static void * ReputationReloadSwap(void);
static void ReputationReloadSwapFree(void *);
#endif


/* Called at preprocessor setup time. Links preprocessor keyword
 * to corresponding preprocessor initialization function.
 *
 * PARAMETERS:	None.
 *
 * RETURNS:	Nothing.
 *
 */
void SetupReputation(void)
{
    /* Link preprocessor keyword to initialization function
     * in the preprocessor list. */
#ifndef SNORT_RELOAD
    _dpd.registerPreproc( "reputation", ReputationInit );
#else
    _dpd.registerPreproc("reputation", ReputationInit, ReputationReload,
            ReputationReloadSwap, ReputationReloadSwapFree);
#endif
}

/* Initializes the Reputation preprocessor module and registers
 * it in the preprocessor list.
 * 
 * PARAMETERS:  
 *
 * argp:   Pointer to argument string to process for configuration data.
 *
 * RETURNS:  Nothing.
 */
static void ReputationInit(char *argp)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    ReputationConfig *pDefaultPolicyConfig = NULL;
    ReputationConfig *pPolicyConfig = NULL;


    if (reputation_config == NULL)
    {
        /*create a context*/
        reputation_config = sfPolicyConfigCreate();
        if (reputation_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate memory "
                    "for Reputation config.\n");
        }

        _dpd.addPreprocConfCheck(ReputationCheckConfig);
        _dpd.registerPreprocStats(REPUTATION_NAME, ReputationPrintStats);
        _dpd.addPreprocExit(ReputationCleanExit, NULL, PRIORITY_LAST, PP_REPUTATION);

#ifdef PERF_PROFILING
        _dpd.addPreprocProfileFunc("reputation", (void *)&reputationPerfStats, 0, _dpd.totalPerfStats);
#endif

    }

    sfPolicyUserPolicySet (reputation_config, policy_id);
    pDefaultPolicyConfig = (ReputationConfig *)sfPolicyUserDataGetDefault(reputation_config);
    pPolicyConfig = (ReputationConfig *)sfPolicyUserDataGetCurrent(reputation_config);
    if ((pPolicyConfig != NULL) && (pDefaultPolicyConfig == NULL))
    {
        DynamicPreprocessorFatalMessage("Reputation preprocessor can only be "
                "configured once.\n");
    }

    pPolicyConfig = (ReputationConfig *)calloc(1, sizeof(ReputationConfig));
    if (!pPolicyConfig)
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory for "
                "Reputation preprocessor configuration.\n");
    }

    sfPolicyUserDataSetCurrent(reputation_config, pPolicyConfig);

    ParseReputationArgs(pPolicyConfig, (u_char *)argp);

    if (0 == pPolicyConfig->numEntries)
    {
        return;
    }

    if (policy_id != 0)
        pPolicyConfig->memcap = pDefaultPolicyConfig->memcap;


    _dpd.addPreproc( ReputationMain, PRIORITY_FIRST, PP_REPUTATION, PROTO_BIT__IP );


}


/*********************************************************************
 * Lookup the iplist table.
 *
 * Arguments:
 *  snort_ip_p  - ip to be searched
 *
 * Returns:
 *  IPdecision -
 *          DECISION_NULL
 *          BLACKLISTED
 *          WHITELISTED
 *
 *********************************************************************/
static inline IPdecision ReputationLookup(snort_ip_p ip)
{
    bw_list * result;

#ifdef SUP_IP6
    DEBUG_WRAP( DebugMessage(DEBUG_REPUTATION, "Lookup address: %s \n",sfip_to_str(ip) ););
#else
    DEBUG_WRAP( DebugMessage(DEBUG_REPUTATION, "Lookup address: %lx \n", ip););
#endif
    if (!reputation_eval_config->scanlocal)
    {
        if (sfip_is_private(ip) )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Private address\n"););
            return DECISION_NULL;
        }
    }

#ifdef SUP_IP6

    result = (bw_list *) sfrt_dir8x_lookup((void *)ip, reputation_eval_config->iplist );

#else

    result = (bw_list *) sfrt_dir8x_lookup((void *)&ip, reputation_eval_config->iplist);

#endif
    /*Check the source and destination*/
    if (NULL != result)
    {
#ifdef SUP_IP6
        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Decision: %s \n",
                WHITELISTED == result->isBlack? "WHITED": "BLACKED" ););
#endif
        return (result->isBlack);
    }
    else
        return DECISION_NULL;

}

/*********************************************************************
 * Make decision based on ip addresses
 *
 * Arguments:
 *  SFSnortPacket * - pointer to packet structure
 *
 * Returns:
 *  IPdecision -
 *          DECISION_NULL
 *          BLACKLISTED
 *          WHITELISTED
 *
 *********************************************************************/
static inline IPdecision ReputationDecision(SFSnortPacket *p)
{
    snort_ip_p ip;
    IPdecision decision;
    IPdecision decision_final = DECISION_NULL;

    /*Check INNER IP, when configured or only one layer*/
    if (( ! p->outer_family )
            ||(INNER == reputation_eval_config->nestedIP)
            ||(BOTH == reputation_eval_config->nestedIP))
    {
        ip = GET_INNER_SRC_IP(((SFSnortPacket *)p));
        decision = ReputationLookup(ip);
        if (DECISION_NULL != decision)
        {
            if ( reputation_eval_config->priority == decision)
                return decision;
            decision_final = decision;
        }


        ip = GET_INNER_DST_IP(((SFSnortPacket *)p));
        decision = ReputationLookup(ip);
        if (DECISION_NULL != decision)
        {
            if ( reputation_eval_config->priority == decision)
                return decision;
            decision_final = decision;
        }
    }
    /*Check OUTER IP*/
    if (( p->outer_family) &&
            ((OUTER == reputation_eval_config->nestedIP)
             ||(BOTH == reputation_eval_config->nestedIP)))
    {
        ip = GET_OUTER_SRC_IP(((SFSnortPacket *)p));
        decision = ReputationLookup(ip);
        if (DECISION_NULL != decision)
        {
            if ( reputation_eval_config->priority == decision)
                return decision;
            decision_final = decision;
        }

        ip = GET_OUTER_DST_IP(((SFSnortPacket *)p));
        decision = ReputationLookup(ip);
        if (DECISION_NULL != decision)
        {
            if ( reputation_eval_config->priority == decision)
                return decision;
            decision_final = decision;
        }

    }
    return (decision_final);
}

/*********************************************************************
 * Main entry point for Reputation processing.
 *
 * Arguments:
 *  SFSnortPacket * - pointer to packet structure
 *
 * Returns:
 *  None
 *
 *********************************************************************/
static inline void ReputationProcess(SFSnortPacket *p)
{

    IPdecision decision;

    decision = ReputationDecision(p);

    if (DECISION_NULL == decision)
    {
      return;
    }
    else if (BLACKLISTED == decision)
    {
        ALERT(REPUTATION_EVENT_BLACKLIST,REPUTATION_EVENT_BLACKLIST_STR);
        _dpd.disableAllDetect(p);
        reputation_stats.blacklisted++;
    }
    else if (WHITELISTED == decision)
    {
        ALERT(REPUTATION_EVENT_WHITELIST,REPUTATION_EVENT_WHITELIST_STR);
        p->flags |= FLAG_IGNORE_PORT;
        _dpd.disableAllDetect(p);
        reputation_stats.whitelisted++;
    }

}
/* Main runtime entry point for Reputation preprocessor.
 * Analyzes Reputation packets for anomalies/exploits.
 * 
 * PARAMETERS:
 *
 * packetp:    Pointer to current packet to process. 
 * contextp:   Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void ReputationMain( void* ipacketp, void* contextp )
{



    PROFILE_VARS;

    DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "%s\n", REPUTATION_DEBUG__START_MSG));

    if (!IsIP((SFSnortPacket*) ipacketp))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,"   -> spp_reputation: Not IP\n"););
        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "%s\n", REPUTATION_DEBUG__END_MSG));
        return;
    }


    sfPolicyUserPolicySet (reputation_config, runtimePolicyId);

    reputation_eval_config = sfPolicyUserDataGetCurrent(reputation_config);

    PREPROC_PROFILE_START(reputationPerfStats);
    /*
     * Start process
     */

    ReputationProcess((SFSnortPacket*) ipacketp);

    DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "%s\n", REPUTATION_DEBUG__END_MSG));
    PREPROC_PROFILE_END(reputationPerfStats);

}

static int ReputationCheckPolicyConfig(tSfPolicyUserContextId config, tSfPolicyId policyId, void* pData)
{
    _dpd.setParserPolicy(policyId);

    return 0;
}
void ReputationCheckConfig(void)
{
    sfPolicyUserDataIterate (reputation_config, ReputationCheckPolicyConfig);
}


static void ReputationCleanExit(int signal, void *data)
{
    if (reputation_config != NULL)
    {
        ReputationFreeConfig(reputation_config);
        reputation_config = NULL;
    }
}
static int ReputationFreeConfigPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
)
{
    ReputationConfig *pPolicyConfig = (ReputationConfig *)pData;

    //do any housekeeping before freeing ReputationConfig

    sfPolicyUserDataClear (config, policyId);

    Reputation_FreeConfig(pPolicyConfig);
    return 0;
}

void ReputationFreeConfig(tSfPolicyUserContextId config)
{
    if (config == NULL)
        return;

    sfPolicyUserDataIterate (config, ReputationFreeConfigPolicy);
    sfPolicyConfigDelete(config);
}
/******************************************************************
 * Print statistics being kept by the preprocessor.
 *
 * Arguments:
 *  int - whether Snort is exiting or not
 *
 * Returns: None
 *
 ******************************************************************/
static void ReputationPrintStats(int exiting)
{

    _dpd.logMsg("Reputation Preprocessor Statistics\n");

    _dpd.logMsg("  Total Memory Allocated: "STDu64"\n", reputation_stats.memoryAllocated);

    if (reputation_stats.blacklisted > 0)
        _dpd.logMsg("  Number of packets blacklisted: "STDu64"\n", reputation_stats.blacklisted);
    if (reputation_stats.whitelisted > 0)
        _dpd.logMsg("  Number of packets whitelisted: "STDu64"\n", reputation_stats.whitelisted);

}
#ifdef SNORT_RELOAD
static void ReputationReload(char *args)
{
    tSfPolicyId policy_id = _dpd.getParserPolicy();
    ReputationConfig * pPolicyConfig = NULL;
    ReputationConfig *pDefaultPolicyConfig = NULL;

    if (reputation_swap_config == NULL)
    {
        //create a context
        reputation_swap_config = sfPolicyConfigCreate();
        if (reputation_swap_config == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate memory "
                    "for Reputation config.\n");
        }

    }

    sfPolicyUserPolicySet (reputation_swap_config, policy_id);
    pPolicyConfig = (ReputationConfig *)sfPolicyUserDataGetCurrent(reputation_swap_config);
    pDefaultPolicyConfig = (ReputationConfig *)sfPolicyUserDataGetDefault(reputation_config);
    if ((pPolicyConfig != NULL) && (pDefaultPolicyConfig == NULL))
    {
        DynamicPreprocessorFatalMessage("Reputation preprocessor can only be "
                "configured once.\n");
    }

    pPolicyConfig = (ReputationConfig *)calloc(1, sizeof(ReputationConfig));
    if (!pPolicyConfig)
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory for "
                "Reputation preprocessor configuration.\n");
    }
    sfPolicyUserDataSetCurrent(reputation_swap_config, pPolicyConfig);

    ParseReputationArgs(pPolicyConfig, (u_char *)args);

    if (0 == pPolicyConfig->numEntries)
    {
        return;
    }
    if (policy_id != 0)
        pPolicyConfig->memcap = pDefaultPolicyConfig->memcap;

    _dpd.addPreproc( ReputationMain, PRIORITY_FIRST, PP_REPUTATION, PROTO_BIT__IP );

}

static int ReputationFreeUnusedConfigPolicy(
        tSfPolicyUserContextId config,
        tSfPolicyId policyId,
        void* pData
)
{
    ReputationConfig *pPolicyConfig = (ReputationConfig *)pData;

    //do any housekeeping before freeing ReputationConfig
    if (pPolicyConfig->ref_count == 0)
    {
        sfPolicyUserDataClear (config, policyId);
        Reputation_FreeConfig(pPolicyConfig);
    }
    return 0;
}

static void * ReputationReloadSwap(void)
{
    tSfPolicyUserContextId old_config = reputation_config;

    if (reputation_swap_config == NULL)
        return NULL;

    reputation_config = reputation_swap_config;
    reputation_swap_config = NULL;

    sfPolicyUserDataIterate (old_config, ReputationFreeUnusedConfigPolicy);

    if (sfPolicyUserPolicyGetActive(old_config) == 0)
    {
        /* No more outstanding configs - free the config array */
        return (void *)old_config;
    }

    return NULL;
}

static void ReputationReloadSwapFree(void *data)
{
    if (data == NULL)
        return;

    ReputationFreeConfig((tSfPolicyUserContextId)data);
}
#endif
