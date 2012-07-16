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

#include <sys/time.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <pcap.h>
#include <string.h>
#include <err.h>
#include <stdlib.h>

#include "tom.h"
#include "string.h"

int
host_log(struct tom *tomi, struct host *h)
{
    char path[256];
    char ip[64];
    FILE *fh;
    struct timeval now;

    printf("sizeof(path) is %u\n", sizeof(path));

    ip_str(&h->ip, ip, sizeof(ip));
    if (strlcpy(path, tomi->log_dir, sizeof(path)) >= sizeof(path) ||
        strlcat(path, "/", sizeof(path)) >= sizeof(path) ||
        strlcat(path, ip, sizeof(path)) >= sizeof(path)) {
        syslog(LOG_ERR, "log path too long");
        return TOM_FAIL;
    }

    fh = fopen(path, "a");
    if (!fh) {
        syslog(LOG_ERR, "Could not open %s for writing", path);
        return TOM_FAIL;
    }

    /* output is: <epoch> <tx bytes> <rx bytes>\n */
    if (fprintf(fh, "%u %u %u\n", h->last_logged, h->tx, h->rx) < 0) {
        syslog(LOG_ERR, "Failed to write to %s\n", path);
        fclose(fh);
        return TOM_FAIL;
    }
    fclose(fh);
    
    gettimeofday(&now, NULL);
    h->last_logged = now.tv_sec;

    printf("Logged ok...\n");
    return TOM_OK;
}

/* 
 * go through list of hosts structures and remove them if they have 
 * not sent data for some time.
 */
int
host_purge(struct tom *tomi)
{
    struct host *thishost; /* this host */
    struct host *prevhost; /* prev host */
    struct host *nexthost; /* next host */

    struct timeval now;
    gettimeofday(&now, NULL);

    /* DEBUG */
    char dbuff[128];

    prevhost = NULL;
    thishost = tomi->hosts;
    while (thishost) {
        nexthost = thishost->next;
        if ((now.tv_sec - thishost->last_traffic) > TOM_PURGETIME) {

            /* debug */
            ip_str(&thishost->ip, dbuff, sizeof(dbuff));
            printf("purging %s (%u hosts remaining in list)\n", 
                   dbuff, 
                   tomi->hosts_size - 1);

            /* if any data pending to write, write it... */
            if (thishost->tx > 0 || thishost->tx > 0)
                host_log(tomi, thishost);

            /* now remove host from list */
            
            if (!prevhost)
                tomi->hosts = nexthost;
            else
                prevhost->next = nexthost;
            free(thishost);
            thishost = nexthost;
            tomi->hosts_size--;
        }
        else {
            prevhost = thishost;
            thishost = nexthost;
        }
    }
    return TOM_OK;
}

/* allocate and init a host structure */
struct host *
host_alloc() {
    struct host *tmphost;

    tmphost = malloc(sizeof(struct host));
    if (!tmphost)
        err(1, NULL);
    
    /* set up some default / sane values */
    tmphost->ip.type = 0;
    tmphost->ip.mask = 0;
    tmphost->ip.next = NULL;
    tmphost->last_traffic = 0;
    tmphost->last_logged = 0;
    tmphost->tx = 0;
    tmphost->rx = 0;
    tmphost->next = NULL;

    return tmphost;
}

/* log tx/rx bytes against a targeted host */
int
host_account(struct tom *tomi, 
             struct pcap_pkthdr *header, 
             struct ip_addr *ip,
             int tx)
{
    /* debug only... */
    char buff[128];
    ip_str(ip, buff, sizeof(buff));


    /* see if ip is in the targeted list */
    struct ip_addr *tgt;
    tgt = tomi->targets;
    while (tgt) {
        if (ip_same_subnet(ip, tgt))
            break;
        tgt = tgt->next;
    }
    if (!tgt) {
        printf("Skipped %s\n", buff);
        return TOM_SKIPPED;
    }

    /* now see if we already have an existing host with same ip */
    struct host *ehost;
    ehost = tomi->hosts;
    while (ehost) {
        if (ip_same(ip, &ehost->ip))
            break;
        ehost = ehost->next;
    }

    /* allocate a new host structure if need be.. */
    if (!ehost) {
        ehost = host_alloc();
        ehost->ip = *ip;
        ehost->last_logged = header->ts.tv_sec;
        ehost->next = tomi->hosts;
        tomi->hosts = ehost;
        tomi->hosts_size++;
    }
    
    ehost->last_traffic = header->ts.tv_sec;
    if (tx)
        ehost->tx += header->caplen;
    else
        ehost->rx += header->caplen;

    /* DEBUG */
    printf("(%u) %s %u tx %u rx \n", tomi->hosts_size, 
           buff, 
           ehost->tx, 
           ehost->rx);

    return TOM_OK;
}


/* add a new target ip address / subnet to watch. */
int 
tom_add_target(struct tom *tomi, struct ip_addr *ip)
{
    /* do some sanity checking... */
    if (!tomi || !ip)
        return TOM_INVALID;
    if (ip->type != TOM_IP4 && ip->type != TOM_IP6)
        return TOM_INVALID;
    if (ip->type == TOM_IP4 && ip->mask > 24)
        return TOM_INVALID;
    if (ip->type == TOM_IP6 && ip->mask > 128)
        return TOM_INVALID;
    
    struct ip_addr *tmp;
    tmp = malloc(sizeof(struct ip_addr));
    if (!tmp) 
        err(1, NULL);

    memcpy(tmp->addr, ip->addr, TOM_ADDR_SIZE);
    tmp->mask = ip->mask;
    tmp->type = ip->type;
    tmp->next = NULL;
    
    if (tomi->targets) {
        struct ip_addr *tmp2;
        tmp2 = tomi->targets;
        while (tmp2) {
            if (!tmp2->next) {
                tmp2->next = tmp;
                break;
            }
            tmp2 = tmp2->next;
        }
    }
    else 
        tomi->targets = tmp;

    return TOM_OK;
}


/* print ip address into buff */
void
ip_str(struct ip_addr *ip, char *buff, size_t buff_size)
{
    if (ip->type == TOM_IP4) {
        snprintf(buff, buff_size, "%u.%u.%u.%u", 
                 ip->addr[0],
                 ip->addr[1],
                 ip->addr[2],
                 ip->addr[3]);
    }
    else 
        snprintf(buff, buff_size, "ip_str(): IP6 not done yet");

}

int
ip_same(struct ip_addr *a, struct ip_addr *b) 
{
    /* check if same ip version, and if type is set to something valid */
    if (a->type != b->type || (a->type != TOM_IP6 && a->type != TOM_IP4))
        return 0;

    int len;
    if (a->type == TOM_IP6)
        len = 16;
    else
        len = 4;

    int x;
    for (x=0; x<len; x++) {
        if (a->addr[x] != b->addr[x])
            return 0;
    }
    return 1;
}

int
ip_same_subnet(struct ip_addr *ip, struct ip_addr *subnet)
{
    if (ip->type != subnet->type)
        return 0;

    int addr_len = 4;  /* 4 bytes or 16 (ip4 or ip6) */
    if (ip->type == TOM_IP6)
        addr_len = 16;

    int len;  /* how much of the subnet mask length we have yet to check */
    int mask; /* individual byte mask (for when we have < 8 bits to check) */
    int x;    /* ip byte position */

    /* loop through each byte of the ip address */
    for (len=subnet->mask, x=0; x<addr_len && len>0; x++, len-= 8) {
        if (len < 8) {
            mask = 8 - len;
            if ((ip->addr[x] >> mask) != (subnet->addr[x] >> mask)) 
                return 0;
            return 1;
        }
        else
            if (ip->addr[x] != subnet->addr[x])
                return 0;
    }
    return 1;
}


/* grabs the dst/src addresses. assumes */
int
tom_process_ip4(uint8_t *packet, struct ip_pair *pair)
{
        uint8_t *h = packet;
        uint16_t header_length = 0xf & *h;

        if (header_length < 5 || header_length > 15) 
            return TOM_SKIPPED;

        h += 12;

        /* store src/dst IP addresses */
        memcpy(pair->src.addr, h, 4);
        pair->src.type = TOM_IP4;
        pair->src.mask = 32;

        h += 4;
        memcpy(pair->dst.addr, h, 4);
        pair->dst.type = TOM_IP4;
        pair->dst.mask = 32;

        return TOM_OK;
}

int
tom_process(struct tom *tomi, struct pcap_pkthdr *header, const uint8_t *packet)
{
	uint8_t *pp;


	pp = (uint8_t*)packet;

    /* skip past the two src/dest mac addreses which are 6 bytes each */
    pp += 12;

    /* now check the QOS or ethernet len / type */
    if ( ntohs(*(uint16_t *)pp) == 0x88A8 ) {
        /* the frame is 802.1ad tagged */
        pp += 8;
    } else if (ntohs( *(uint16_t *)pp) == 0x8100) {
        /* the frame is 802.1Q tagged */
        pp += 4;
    } else if (ntohs(*(uint16_t *)pp) != 0x0800) {
        /* is not an IP packet... */
        return TOM_SKIPPED;
    }

    /* skip past ether type / size field */
    pp += 2;

    /* go grab the src/dst addresses */
    struct ip_pair pair;
    int ret = TOM_FAIL;
    switch (*pp >> 4) {
    case 4: 
        /* IPV4 */
        ret = tom_process_ip4(pp, &pair);
        break;
    default:
        printf("Got some other bullshit packet version...\n");
        break;
    }

    if (ret != TOM_OK)
        return ret;

    /* DEBUG shit... */
    /* char src_buff[128]; */
    /* char dst_buff[128]; */
    /* ip_str(&pair.src, src_buff, sizeof(src_buff)); */
    /* ip_str(&pair.dst, dst_buff, sizeof(dst_buff)); */
    /* printf("from %s to %s %u bytes\n", src_buff, dst_buff, header->caplen); */

    /* now do some accounting... */
    host_account(tomi, header, &pair.src, 1);
    host_account(tomi, header, &pair.dst, 0);

    return TOM_OK;
}

/* capture and process a single packet, and return. */
int
tom_capture_one(struct tom *tomi)
{
    struct pcap_pkthdr *hdr;
    const uint8_t      *packet;
    int ret;

    ret = pcap_next_ex(tomi->pcap_handle,
                       &hdr,
                       &packet);
    switch (ret) {
    case 1:  /* packet captured ok */
        return tom_process(tomi, hdr, packet);
        break;
    case 0:  /* timeout */
        printf("TIMEOUT!\n");
        return TOM_TIMEOUT;
        break;
    default:
        syslog(LOG_ERR, "%s", pcap_geterr(tomi->pcap_handle));
        tom_free(tomi);
        return TOM_FAIL;
    }
    return TOM_FAIL;
}

/* free memory and close handles */
void
tom_free(struct tom *tomi)
{
    if (tomi->interface_name) {
        free(tomi->interface_name);
        tomi->interface_name = NULL;
    }
    
    if (tomi->pcap_handle) {
        pcap_close(tomi->pcap_handle);
        tomi->pcap_handle = NULL;
    }

    /* free up the targets linked list */
    struct ip_addr *ip;
    struct ip_addr *next;
    ip = tomi->targets;
    while (ip) {
        next = ip->next;
        free(ip);
        ip = next;
    }
    tomi->targets = NULL;
    
    /* free up the hosts */
    struct host *tmphost;
    struct host *nexthost;
    tmphost = tomi->hosts;
    while (tmphost) {
        nexthost = tmphost->next;
        free(tmphost);
        tmphost = nexthost;
        tomi->hosts_size--;
    }
    tomi->hosts = NULL;
    
}

/* opens up a pcap session and gets shit ready */
int
tom_init(struct tom *tomi, char *iface_name, const char *log_dir)
{
    if (!tomi) 
        return TOM_INVALID;

    /* set things to NULL/defaults */
    tomi->pcap_handle = NULL;
    tomi->interface_name = NULL;
    tomi->ebuff[0] = '\0';
    tomi->targets = NULL;
    tomi->hosts = NULL;
    tomi->hosts_size = 0;

    tomi->interface_name = strdup(iface_name);
    if (!tomi->interface_name)
        err(1, NULL);

    tomi->log_dir = strdup(log_dir);
    if (!tomi->log_dir)
        err(1, NULL);
    printf("Log dir is '%s'\n", tomi->log_dir);


    /* open the pcap device */
    tomi->pcap_handle = pcap_open_live(tomi->interface_name,
                                       TOM_CAPLEN,
                                       1, /* promiscuous mode */
                                       0, /* no timeout */
                                       tomi->ebuff);

    /* any luck? */
    if (!tomi->pcap_handle) {
        warn("pcap_open_live() %s", tomi->ebuff);
        tom_free(tomi);
        return TOM_FAIL;
    }

    /* TODO: set pcap filter here. */

    return TOM_OK;
}

