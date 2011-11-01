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
    int             size_all, size;
    FILE*           fp;
    int             consumed = 0;
    int             num_certs = 0;
    sfip_t          *src_ip, *dst_ip;
    char            time_buf[128];
    char            filename[128];
    struct timeval  time;
    time_t          now;
    struct tm*      ts;
    
    // Get the current time
    if (gettimeofday(&time, NULL) != 0) {
        perror("Couldn't get time of day");
        return;
    }
    
    // Format and print the time
    now = time.tv_sec;
    ts = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%y-%m-%d %H-%M-%S", ts);
    
    size_all = THREE_BYTE_LEN(pkt);
    printf("size of all certificates is %d\n", size_all);
    
    snprintf(filename, sizeof(filename), "%s%s-%ld.meta", LOG_DIR, time_buf, time.tv_usec);
    
    printf("\nlogging certificate(s)\n");
    
    fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Couldn't open file %s\n", filename);
        fp = stdout;
    }
    
    src_ip = &(packet->ip4h->ip_src);
    dst_ip = &(packet->ip4h->ip_dst);
    fprintf(fp, "src_ip = %s\n", sfip_ntoa(src_ip));
    fprintf(fp, "dst_ip = %s\n", sfip_ntoa(dst_ip));
    fprintf(fp, "version = %d.%d\n", record->major, record->minor);
    fprintf(fp, "tcp_seq = %u\n", packet->tcp_header->sequence);
    fprintf(fp, "src_port = %d\n", packet->src_port);
    fprintf(fp, "dst_port = %d\n", packet->dst_port);
    fprintf(fp, "num_bytes = %d\n", size_p);
    
    fclose(fp);
    
    
    for (pkt += 3; consumed < size_all; num_certs++) {
        size = THREE_BYTE_LEN(pkt);
        printf("size of certificate %d is %d\n", num_certs, size);
        write_to_log(pkt+3, size, packet->tcp_header->sequence, time);
        pkt += size + 3;
        consumed += size + 3;
    }
    
}

int write_to_log(const uint8_t *pkt, int size, uint32_t sqn_num, struct timeval time)
{
    int             i;
    FILE*           fp;
    char*           buffer;
    char            filename[128];
    char            time_buf[128];
    time_t          now;
    struct tm*      ts;
    
    //encode certificate in base64
    buffer = encode_base_64((char*)pkt, &size);
    printf("\nencoded size is %d\n", size);
    
    // Format and print the time
    now = time.tv_sec;
    ts = localtime(&now);
    strftime(time_buf, sizeof(time_buf), "%y-%m-%d %H-%M-%S", ts);
    
//    (void)strncat(filename, time_buf, strlen(time_buf));
    
    snprintf(filename, sizeof(filename), "%s%s-%ld.pem", LOG_DIR, time_buf, time.tv_usec);
    
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
//    int i;
    
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