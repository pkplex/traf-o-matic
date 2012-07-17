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

#include <syslog.h>
#include <stdio.h>
#include "tom.h"

int 
main(int argc, char **argv) 
{
    struct tom tomi;

    /* sort out syslog */
    openlog("tom", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    if (tom_init(&tomi, "eth1", "./logs") != TOM_OK) {
        printf("Well, shit.\n");
        return 1;
    }

    struct ip_addr a;
    a.type = TOM_IP4;
    a.mask = 12;
    a.addr[0] = 172;
    a.addr[1] = 16;
    a.addr[2] = 0;
    a.addr[3] = 0;
    tom_add_target(&tomi, &a);

    struct ip_addr b;
    b.type = TOM_IP4;
    b.mask = 24;
    b.addr[0] = 192;
    b.addr[1] = 168;
    b.addr[2] = 5;
    b.addr[3] = 0;
    tom_add_target(&tomi, &b);

    syslog(LOG_INFO, "Starting");

    while (tom_capture_one(&tomi) != TOM_FAIL) { 
        /* DEBUG ONLY: wont be running purge each capture */
        host_purge(&tomi);
    }

    tom_free(&tomi);
    return 0;
}
