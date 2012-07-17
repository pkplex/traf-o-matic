/*
 * Copyright (c) 2012 Joshua Sandbrook.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _tom_h
#define _tom_h

#include <pcap.h>
#include <stdint.h>

/* wee enum for error / return values */
enum {
    TOM_OK = 0,                 /* no problems */
    TOM_FAIL,                   /* problem, pcap closed, missing file, etc */
    TOM_INVALID,                /* invalid argument */
    TOM_TIMEOUT,                /* timeout */
    TOM_SKIPPED,                /* ignored a boring or invalid packet */
    TOM_IP4,                    /* is an IP version 4 packet */
    TOM_IP6                     /* is an IP version 6 packet */
};

#define TOM_CAPLEN    65536     /* max packet capture size */
#define TOM_PURGETIME 60        /* time till expiry of inactive hosts  */
#define TOM_LOGTIME   30        /* time till log should be written  */


/* structure which holds a single ip address */
#define TOM_ADDR_SIZE 16
struct ip_addr {
    uint8_t  addr[TOM_ADDR_SIZE]; /* holds either 4 byte IP4 or 16 byte IP6 */
    uint8_t  mask;                /* subnet mask length (ie, /24) */
    uint8_t  type;                /* IP4 or IP6 */
    struct ip_addr *next; 
};

/* a monitored host */
struct host {
    struct ip_addr ip;
    uint32_t       last_traffic; /* epoch time of last tx/rx */
    uint32_t       last_logged; /* epoch time of last log wirte */
    uint32_t       tx;
    uint32_t       rx;
    struct host   *next;
};

/* instance to hold all the shit required for capturing stuff */
struct tom {
    pcap_t         *pcap_handle;
    char           *interface_name;
    char            ebuff[PCAP_ERRBUF_SIZE];
    struct ip_addr *targets;
    struct host    *hosts;
    uint32_t        hosts_size;
    char           *log_dir;
};


/* contains src/dst ip addresses. */
struct ip_pair {
    struct ip_addr src;
    struct ip_addr dst;
};

extern int   host_purge(struct tom *tomi);
extern int   tom_add_target(struct tom *tomi, struct ip_addr *ip);
extern void  ip_str(struct ip_addr *ip, char *buff, size_t buff_size);
extern int   ip_same(struct ip_addr *a, struct ip_addr *b);
extern int   ip_same_subnet(struct ip_addr *ip, struct ip_addr *subnet);
extern int   tom_capture_one(struct tom *tomi);
extern void  tom_free(struct tom *tomi);
extern int   tom_init(struct tom *tomi, char *interface_name, const char *log_dir);


#endif
