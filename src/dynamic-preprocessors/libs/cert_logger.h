//
//  cert_logger.h
//  SSLCertSnorter
//
//  Created by Andy on 10/6/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#ifndef CERT_LOGGER_H
#define CERT_LOGGER_H

#include "cencode.h"
#include "sf_snort_packet.h"
#include "sf_ip.h"
#include "ssl.h"
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

#define THREE_BYTE_LEN(x) (x[2] | x[1] << 8 | x[0] << 16)
#define COUNTER_BUF_SIZE 10
#define LOG_DIR "/var/log/snort/certs/"

//#define BUF_SIZE 4096

void SSL_cert_dump(const uint8_t *pkt , int size_p,
                   const SFSnortPacket *packet,
                   const SSL_record_t *record);

char* encode_base_64(const char *cert, int *length);

int write_to_log(const uint8_t *pkt, int size, uint32_t sqn_num, struct timeval time);

//typedef struct _certMetaData
//{
//    char *srcIP;
//    char *dstIP;
//    uint32_t min_version;
//    uint32_t maj_version;
//    uint32_t sqn_num;
//    
//} certMetaData;

#endif