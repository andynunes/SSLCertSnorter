/****************************************************************************
 * Copyright (C) 2011-2011 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************
 * Provides convenience functions for parsing and querying configuration.
 *
 * 6/11/2011 - Initial implementation ... Hui Cao <hcao@sourcefire.com>
 *
 ****************************************************************************/

#ifndef _REPUTATION_CONFIG_H_
#define _REPUTATION_CONFIG_H_

#include "sfPolicyUserData.h"
#include "snort_bounds.h"
#include "reputation_debug.h"
#include "sf_ip.h"

#define REPUTATION_NAME  "reputation"

typedef enum _NestedIP
{
    INNER,
    OUTER,
    BOTH
}NestedIP;

typedef enum _IPdecision
{
    DECISION_NULL ,
    BLACKLISTED ,
    WHITELISTED
}IPdecision;

/*
 * Reputation preprocessor configuration.
 *
 * memcap:  the memcap for IP table.
 * numEntries: number of entries in the table
 * scanlocal: to scan local network
 * prioirity: the priority of whitelist, blacklist
 * nestedIP: which IP address to use when IP encapsulation
 * iplist: the IP table
 * ref_count: reference account
 */
typedef struct _reputationConfig
{
	uint32_t memcap;
	int numEntries;
    uint8_t  scanlocal;
	IPdecision priority;
	NestedIP nestedIP;
	table_t *iplist;
	int ref_count;

} ReputationConfig;



typedef struct {
    IPdecision isBlack;
} bw_list;

/********************************************************************
 * Public function prototypes
 ********************************************************************/
void  Reputation_FreeConfig(ReputationConfig *);
void  ParseReputationArgs(ReputationConfig *, u_char*);


#endif
