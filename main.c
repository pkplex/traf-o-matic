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

#include <sys/types.h>

#include <unistd.h>
#include <features.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <err.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "tom.h"
#include "string.h"

/* attempt to parse an IP */
struct ip_addr *
parse_ip(const char *ip)
{
    unsigned int t[5];
    int x;

    if (sscanf(ip, "%u.%u.%u.%u/%u", &t[0], &t[1], &t[2], &t[3], &t[4]) != 5)
        return NULL;

    /* check for invalid values */
    for (x=0; x<4; x++) {
        if (t[x] > 255) 
            return NULL;
    }
    if (t[4] > 32)
        return NULL;

    /* construct a ip_addr to return */
    struct ip_addr *ret;
    ret = malloc(sizeof(struct ip_addr));
    if (!ret)
        err(1, NULL);

    ret->type = TOM_IP4;
    ret->addr[0] = t[0];
    ret->addr[1] = t[1];
    ret->addr[2] = t[2];
    ret->addr[3] = t[3];
    ret->mask = t[4];
    ret->next = NULL;

    return ret;
}

int 
main(int argc, char **argv) 
{
    struct tom      tomi;
    int             dontfork = 0;
    int             oret;
    char interface[64]       = { '\0' };
    char logdir[256]         = { '\0' };
    char user[64]            = { '\0' };
    char group[64]           = { '\0' };
    uid_t           uid;
    gid_t           gid;
    struct ip_addr *targets  = NULL;
    struct ip_addr *ipret    = NULL;
    struct passwd  *pw       = NULL;
    struct group   *gr       = NULL;

    while ((oret = getopt(argc, argv, "fi:l:t:u:")) != -1) {
        switch (oret) {
        case 'u':
            if (strlcpy(user, optarg, sizeof(user)) >= sizeof(user))
                errx(1, "username too long\n");
            break;
        case 'g':
            if (strlcpy(group, optarg, sizeof(group)) >= sizeof(group))
                errx(1, "group too long\n");
            break;
        case 'f':
            dontfork = 1;
            break;
        case 'i':
            strlcpy(interface, optarg, sizeof(interface));
            break;
        case 'l':
            strlcpy(logdir, optarg, sizeof(logdir));
            break;
        case 't':
            if (!(ipret = parse_ip(optarg)))
                errx(1, "%s is a invalid ip address", optarg);
            if (!targets)
                targets = ipret;
            else {
                ipret->next = targets;
                targets = ipret;
            }
            break;
        default: 
            errx(1, "Unknown option -%c", oret);
            break;
        }
    }

    if (interface[0] == '\0')
        errx(1, "No interface name given");
    if (logdir[0] == '\0')
        errx(1, "No log directory given");

    /* get the username and group */
    if (user[0] == '\0')
        errx(1, "No username specified");


    if ((pw = getpwnam(user)) == NULL)
		errx(1, "no such user %s", user);
    gid = pw->pw_gid;
    uid = pw->pw_uid;


    if (group[0] != '\0') {
        if ((gr = getgrnam(group)) == NULL)
            errx(1, "no such group %s", group);
        else
            gid = gr->gr_gid;
    }

    /* sort out syslog */
    openlog("tom", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    /* open/setup pcap and what not */
    if (tom_init(&tomi, interface, logdir) != TOM_OK)
        return 1;

    /* add the ip addresses we want to monitor */
    ipret = targets;
    while (targets) {
        if (tom_add_target(&tomi, targets) != TOM_OK)
            errx(1, "invalid target ip address");
        ipret = targets->next;
        free(targets);
        targets = ipret;
    }
    targets = NULL;

    syslog(LOG_INFO, "Dropping priledges");
    if (setregid(gid, gid) == -1)
        err(1, "setregid()");

    if (setreuid(uid, uid) == -1)
        err(1, "setreuid()");

    if (!dontfork) 
        if (daemon(1, 0))
            err(1, "daemon()");

    syslog(LOG_INFO, "started");

    /* int x = 0; */
    while (tom_capture_one(&tomi) != TOM_FAIL) { 
        /* DEBUG ONLY: wont be running purge each capture */
        host_purge(&tomi);
        /* x++; */
        /* printf("%i\n", x); */
        /* if (x > 100) */
        /*     break; */
    }

    tom_free(&tomi);
    return 0;
}
