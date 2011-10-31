//
//  cert_logger.c
//  SSLCertSnorter
//
//  Created by Andy on 10/6/11.
//  Copyright 2011 __MyCompanyName__. All rights reserved.
//

#include "cert_logger.h"

void SSL_cert_dump(const uint8_t *pkt , int size_p,
                   const SFSnortPacket *packet,
                   const SSL_record_t *record)
{
    int i, size_all, size;
    char *buffer;
    int consumed = 0;
    int num_certs = 0;
    sfip_t *src_ip, *dst_ip;
    
    src_ip = &(packet->ip4h->ip_src);
    dst_ip = &(packet->ip4h->ip_dst);
    printf("\nlogging certificate(s)\n");
    printf("src IP = %s\n", sfip_ntoa(src_ip));
    printf("dst IP = %s\n", sfip_ntoa(dst_ip));
    printf("version = %d.%d\n", record->major, record->minor);
//    printf("tcp sequence = %u\n", packet->tcp_header->sequence);
//    printf("ip src port = %d\n", packet->src_port);
//    printf("ip dst port = %d\n", packet->dst_port);
//    printf("dumping %d bytes\n", size_p);
//    for (i=0; i<size_p; i++) {
//        putchar(pkt[i]);
////        putchar((packet->payload)[i]);
//    }
    
    size_all = THREE_BYTE_LEN(pkt);
    printf("size of all certificates is %d\n", size_all);
    
    for (pkt += 3; consumed < size_all; num_certs++) {
        size = THREE_BYTE_LEN(pkt);
        printf("size of certificate %d is %d\n", num_certs, size);
        write_to_log(pkt+3, size, packet->tcp_header->sequence);
        pkt += size + 3;
        consumed += size + 3;
    }
    
    
}

int write_to_log(const uint8_t *pkt, int size, uint32_t sqn_num)
{
    int         i;
    FILE*       fp;
    char*       buffer;
    time_t      now;
    struct tm*  ts;
    char        filename[80];
    char        time_buf[80];
    
    //encode certificate in base64
    buffer = encode_base_64((char*)pkt, &size);
    printf("\nencoded size is %d\n", size);
    
    /* Get the current time */
    now = time(NULL);
    
    /* Format and print the time */
    ts = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%y-%m-%d %H-%M-%S", ts);
    
//    (void)strncat(filename, time_buf, strlen(time_buf));
    
    snprintf(filename, sizeof(filename), "%s%s.%u.pem", LOG_DIR, time_buf, sqn_num);
    
    printf("filename = %s\n", filename);
    
    fp = fopen(filename, "a");
    if (!fp) {
        fprintf(stderr, "Couldn't open file %s\n", filename);
        fp = stdout;
    }
    
    fprintf(fp, "-----BEGIN CERTIFICATE-----\n");
    for (i=0; i<size; i++)
        fputc(buffer[i], fp);
    fprintf(fp, "-----END CERTIFICATE-----\n");
  
    fclose(fp);
    free(buffer);
    return 0;
}

//uint32_t get_counter()
//{
//    uint32_t    count;
//    FILE*       fp;
//    char*       filename = "/var/log/snort/certs/count";
//    char        buf[COUNTER_BUF_SIZE];
//    size_t      sz;
//    
//    fp = fopen(filename, "r");
//    if (!fp) {
//        perror("Couldn't open counter file for reading");
//        return 0;
//    }
//    sz = fread(buf, COUNTER_BUF_SIZE-1, 1, fp);
//    if (sz <= 0) {
//        perror("Error reading counter file");
//        return 0;
//    }
//    
//    
//    fclose(fp);
//    return count;
//}

char* encode_base_64(const char *cert, int *length)
{
    base64_encodestate state;
    char buf[(*length)*2];
    char *alloced_buf;
    int first_len;
    int second_len;
    int i;
    
    base64_init_encodestate(&state);
    
    first_len = base64_encode_block(cert, *length, buf, &state);
//    printf("\nfirst chunk is %d long\n", first_len);
//    for (i=0; i<first_len; i++)
//        fputc(buf[i], stdout);
    
//    first_len += base64_encode_blockend(buf, &state);
    second_len = base64_encode_blockend(buf+first_len, &state);
//    printf("\nsecond chunk is %d long\n", second_len);
//    for (i=0; i<second_len; i++)
//        fputc(buf[i+first_len], stdout);
    
    *length = first_len + second_len;
    
    base64_init_encodestate(&state);
    
    alloced_buf = (char*)malloc(*length+1);
    memcpy(alloced_buf, buf, *length);
    
    return alloced_buf;
}