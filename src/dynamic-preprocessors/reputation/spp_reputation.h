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
 * spp_reputation.h: Definitions, structs, function prototype(s) for
 *		the Reputation preprocessor.
 * Author: Hui Cao
 */

#ifndef SPP_REPUTATION_H
#define SPP_REPUTATION_H

#include "sf_types.h"
#include "sfPolicy.h"
#include "sfPolicyUserData.h"
#include "snort_bounds.h"
#include "sf_ip.h"
#include "reputation_config.h"


/*
 * Generator id. Define here the same as the official registry
 * in generators.h
 */
#define GENERATOR_SPP_REPUTATION	136

/* Ultimately calls SnortEventqAdd */
/* Arguments are: gid, sid, rev, classification, priority, message, rule_info */
#define ALERT(x,y) { _dpd.alertAdd(GENERATOR_SPP_REPUTATION, x, 1, 0, 3, y, 0 ); }

#define REPUTATION_EVENT_BLACKLIST       1
#define REPUTATION_EVENT_BLACKLIST_STR     "(spp_reputation) packets blacklisted"
#define REPUTATION_EVENT_WHITELIST       2
#define REPUTATION_EVENT_WHITELIST_STR     "(spp_reputation) packets whitelisted"


typedef struct _Reputation_Stats
{
    uint64_t blacklisted;
    uint64_t whitelisted;
    uint64_t memoryAllocated;

} Reputation_Stats;

extern Reputation_Stats reputation_stats;
extern int totalNumEntries;
extern ReputationConfig *reputation_eval_config;
extern tSfPolicyUserContextId reputation_config;


/* Prototypes for public interface */
void SetupReputation(void);

#endif /* SPP_REPUTATION_H */
