/*
 * ipv6cp.c - PPP IPv6 Control Protocol.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 * Copyright (c) 2017 RaydoNetworks.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pppd.h"
#include "fsm.h"
#include "ipv6cp.h"
#include "pathnames.h"

/* global vars */
fsm ipv6cp_fsm[NUM_PPP];		/* IPV6CP fsm structure */
ipv6cp_options ipv6cp_wantoptions[NUM_PPP];	/* Options that we want to request */
ipv6cp_options ipv6cp_gotoptions[NUM_PPP];	/* Options that peer ack'd */
ipv6cp_options ipv6cp_allowoptions[NUM_PPP];	/* Options we allow peer to request */
ipv6cp_options ipv6cp_hisoptions[NUM_PPP];	/* Options that we ack'd */

/* Hook for a plugin to know when IPv6 protocol has come up */
void (*ipv6_up_hook) __P((void)) = NULL;

/* Hook for a plugin to know when IPv6 protocol has come down */
void (*ipv6_down_hook) __P((void)) = NULL;

/* Notifiers for when IPV6CP goes up and down */
struct notifier *ipv6_up_notifier = NULL;
struct notifier *ipv6_down_notifier = NULL;

/* local vars */
static int ipv6cp_is_up[NUM_PPP];		/* have called np_up() */
static int ipv6cp_is_open[NUM_PPP];		/* haven't called np_finished() */

/*
 * Callbacks for fsm code.
 */
static void ipv6cp_resetci __P((fsm *));
static int  ipv6cp_cilen __P((fsm *));
static void ipv6cp_addci __P((fsm *, u_char *, int *));
static int  ipv6cp_ackci __P((fsm *, u_char *, int));
static int  ipv6cp_nakci __P((fsm *, u_char *, int, int));
static int  ipv6cp_rejci __P((fsm *, u_char *, int));
static int  ipv6cp_reqci __P((fsm *, u_char *, int *, int));
static void ipv6cp_up __P((fsm *));
static void ipv6cp_down __P((fsm *));
static void ipv6cp_starting __P((fsm *));
static void ipv6cp_finished __P((fsm *));
static void ipv6cp_protrej __P((int));

static struct fsm_callbacks ipv6cp_callbacks = {
    ipv6cp_resetci,
    ipv6cp_cilen,
    ipv6cp_addci,
    ipv6cp_ackci,
    ipv6cp_nakci,
    ipv6cp_rejci,
    ipv6cp_reqci,
    ipv6cp_up,
    ipv6cp_down,
    ipv6cp_starting,
    ipv6cp_finished,
    ipv6cp_protrej,
    NULL,
    "IPV6CP"
};

/*
 * ipv6cp_init - Initialize IPv6CP.
 */
static void
ipv6cp_init(unit)
    int unit;
{
    fsm *f = &ipv6cp_fsm[unit];

    f->unit = unit;
    f->protocol = PPP_IPV6CP;
    f->callbacks = &ipv6cp_callbacks;
    fsm_init(f);

    /* Set default interface identifiers */
    /* Use random identifier for now */
    ipv6cp_wantoptions[unit].neg_ifaceid = 1;
    ipv6cp_wantoptions[unit].req_ifaceid = 1;
    ipv6cp_wantoptions[unit].accept_local = 1;
    ipv6cp_wantoptions[unit].accept_remote = 1;
    
    /* Generate random interface identifiers */
    {
        int i;
        for (i = 0; i < 8; i++) {
            ipv6cp_wantoptions[unit].ourid[i] = (u_char)(rand() & 0xff);
            ipv6cp_wantoptions[unit].hisid[i] = 0;
        }
    }

    ipv6cp_allowoptions[unit].neg_ifaceid = 1;
    ipv6cp_gotoptions[unit].neg_ifaceid = 0;
    ipv6cp_hisoptions[unit].neg_ifaceid = 0;
}


/*
 * ipv6cp_resetci - Reset our Configuration Information
 */
static void
ipv6cp_resetci(f)
    fsm *f;
{
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];
    ipv6cp_options *ao = &ipv6cp_allowoptions[f->unit];

    ipv6cp_gotoptions[f->unit] = *wo;
    ipv6cp_hisoptions[f->unit].neg_ifaceid = 0;
    
    /* Ensure our identifier is not zero */
    if (wo->ourid[0] == 0 && wo->ourid[1] == 0 &&
        wo->ourid[2] == 0 && wo->ourid[3] == 0 &&
        wo->ourid[4] == 0 && wo->ourid[5] == 0 &&
        wo->ourid[6] == 0 && wo->ourid[7] == 0) {
        wo->ourid[6] = 0x02;  /* Mark as random */
        wo->ourid[7] = 0x00;
    }
}


/*
 * ipv6cp_cilen - Length of our Configuration Information
 */
static int
ipv6cp_cilen(f)
    fsm *f;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];

    return (go->neg_ifaceid? 2+8: 0);
}


/*
 * ipv6cp_addci - Add our Configuration Information
 */
static void
ipv6cp_addci(f, cp, lenp)
    fsm *f;
    u_char *cp;
    int *lenp;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];

    if (go->neg_ifaceid) {
        PUTCHAR(CI_IFACEID, cp);
        PUTCHAR(2+8, cp);
        BCOPY(go->ourid, cp, 8);
        cp += 8;
    }
}


/*
 * ipv6cp_ackci - ACK our Configuration Information
 */
static int
ipv6cp_ackci(f, cp, len)
    fsm *f;
    u_char *cp;
    int len;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    int ret = 1;

    if (go->neg_ifaceid) {
        int citype, cilen;
        u_char ci[8];
        
        if (len < 2+8)
            return 0;
        GETCHAR(citype, cp);
        GETCHAR(cilen, cp);
        if (citype != CI_IFACEID || cilen != 2+8)
            return 0;
        BCOPY(cp, ci, 8);
        cp += 8;
        len -= 2+8;
        
        if (bcmp(ci, go->ourid, 8) != 0) {
            ret = 0;
        }
    }

    if (len != 0)
        ret = 0;
    return ret;
}


/*
 * ipv6cp_nakci - NAK our Configuration Information
 */
static int
ipv6cp_nakci(f, cp, len, treat_as_reject)
    fsm *f;
    u_char *cp;
    int len;
    int treat_as_reject;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];
    ipv6cp_options *ho = &ipv6cp_hisoptions[f->unit];
    int ret = 1;

    if (go->neg_ifaceid) {
        int citype, cilen;
        
        if (len < 2)
            return 0;
        GETCHAR(citype, cp);
        GETCHAR(cilen, cp);
        len -= 2;
        
        if (citype == CI_IFACEID) {
            if (cilen != 2+8)
                return 0;
            if (len < 8)
                return 0;
                
            if (treat_as_reject) {
                /* Reject the identifier */
                BCOPY(cp, ho->hisid, 8);
                ho->neg_ifaceid = 1;
            } else {
                /* Use peer's suggested identifier as our identifier */
                BCOPY(cp, go->ourid, 8);
            }
            cp += 8;
            len -= 8;
        }
    }

    if (len != 0)
        ret = 0;
    return ret;
}


/*
 * ipv6cp_rejci - Reject our Configuration Information
 */
static int
ipv6cp_rejci(f, cp, len)
    fsm *f;
    u_char *cp;
    int len;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    ipv6cp_options *ho = &ipv6cp_hisoptions[f->unit];
    int ret = 1;

    if (go->neg_ifaceid) {
        int citype, cilen;
        
        if (len < 2)
            return 0;
        GETCHAR(citype, cp);
        GETCHAR(cilen, cp);
        len -= 2;
        
        if (citype == CI_IFACEID) {
            if (cilen != 2+8)
                return 0;
            if (len < 8)
                return 0;
                
            /* Reject the identifier */
            BCOPY(cp, ho->hisid, 8);
            ho->neg_ifaceid = 1;
            go->neg_ifaceid = 0;
            cp += 8;
            len -= 8;
        }
    }

    if (len != 0)
        ret = 0;
    return ret;
}


/*
 * ipv6cp_reqci - Request peer's Configuration Information
 */
static int
ipv6cp_reqci(f, inp, len, reject_as_is)
    fsm *f;
    u_char *inp;
    int *len;
    int reject_as_is;
{
    ipv6cp_options *wo = &ipv6cp_wantoptions[f->unit];
    ipv6cp_options *ao = &ipv6cp_allowoptions[f->unit];
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    int ret = CONFACK;
    int cilen;
    int i;
    
    while (*len > 0) {
        int citype, olen;
        
        GETCHAR(citype, inp);
        GETCHAR(olen, inp);
        
        if (olen < 2 || olen > *len) {
            /* Invalid length */
            ret = CONFREJ;
            break;
        }
        
        if (citype == CI_IFACEID) {
            u_char ci[8];
            
            if (olen != 2+8) {
                /* Invalid length for interface identifier */
                ret = CONFREJ;
                if (ret == CONFACK)
                    ret = CONFREJ;
                break;
            }
            
            BCOPY(inp, ci, 8);
            inp += 8;
            *len -= 2+8;
            
            /* Check if we accept the identifier */
            if (reject_as_is || !wo->neg_ifaceid || !ao->neg_ifaceid) {
                /* Reject */
                ret = CONFREJ;
                if (ret == CONFACK)
                    ret = CONFREJ;
            } else {
                /* Accept and use as our identifier */
                for (i = 0; i < 8; i++) {
                    if (ci[i] != 0)
                        break;
                }
                if (i < 8) {
                    /* Non-zero identifier, accept it */
                    BCOPY(ci, go->ourid, 8);
                    go->neg_ifaceid = 1;
                } else {
                    /* Zero identifier, reject it */
                    ret = CONFREJ;
                    if (ret == CONFACK)
                        ret = CONFREJ;
                }
            }
        } else {
            /* Unknown option, reject it */
            ret = CONFREJ;
            if (ret == CONFACK)
                ret = CONFREJ;
            break;
        }
    }

    return ret;
}


/*
 * ipv6cp_up - IPv6CP has come up
 */
static void
ipv6cp_up(f)
    fsm *f;
{
    ipv6cp_options *go = &ipv6cp_gotoptions[f->unit];
    
    if (go->neg_ifaceid) {
        dbglog("ipv6cp: up event - interface identifier negotiated");
    }
    
    ipv6cp_is_up[f->unit] = 1;
    
    /* Call the up hook if defined */
    if (ipv6_up_hook)
        ipv6_up_hook();
        
    /* Notify listeners */
    notify(ipv6_up_notifier, 0);
}


/*
 * ipv6cp_down - IPv6CP has gone down
 */
static void
ipv6cp_down(f)
    fsm *f;
{
    ipv6cp_is_up[f->unit] = 0;
    
    /* Call the down hook if defined */
    if (ipv6_down_hook)
        ipv6_down_hook();
        
    /* Notify listeners */
    notify(ipv6_down_notifier, 0);
}


/*
 * ipv6cp_starting - IPv6CP needs to start
 */
static void
ipv6cp_starting(f)
    fsm *f;
{
    ipv6cp_is_open[f->unit] = 0;
}


/*
 * ipv6cp_finished - IPv6CP finished
 */
static void
ipv6cp_finished(f)
    fsm *f;
{
    ipv6cp_is_open[f->unit] = 0;
    ipv6cp_is_up[f->unit] = 0;
}


/*
 * ipv6cp_protrej - Protocol Reject received
 */
static void
ipv6cp_protrej(unit)
    int unit;
{
    /* Protocol rejected, bring down the protocol */
    if (ipv6cp_is_up[unit]) {
        ipv6cp_is_up[unit] = 0;
        if (ipv6_down_hook)
            ipv6_down_hook();
    }
    ipv6cp_is_open[unit] = 0;
}


/*
 * ipv6cp_input - Handle IPv6CP packet
 */
static void
ipv6cp_input(unit, p, len)
    int unit;
    u_char *p;
    int len;
{
    fsm *f = &ipv6cp_fsm[unit];
    
    fsm_input(f, p, len);
}


/*
 * ipv6cp_protrej - Protocol Reject for IPv6CP
 */
static void
ipv6cp_protrej_unit(unit)
    int unit;
{
    fsm *f = &ipv6cp_fsm[unit];
    
    fsm_protreject(f);
}


/*
 * ipv6cp_lowerup - Lower layer is up
 */
static void
ipv6cp_lowerup(unit)
    int unit;
{
    fsm *f = &ipv6cp_fsm[unit];
    
    fsm_lowerup(f);
}


/*
 * ipv6cp_lowerdown - Lower layer is down
 */
static void
ipv6cp_lowerdown(unit)
    int unit;
{
    fsm *f = &ipv6cp_fsm[unit];
    
    fsm_lowerdown(f);
}


/*
 * ipv6cp_open - Open IPv6CP
 */
static void
ipv6cp_open(unit)
    int unit;
{
    fsm *f = &ipv6cp_fsm[unit];
    
    if (ipv6cp_is_open[unit])
        return;
        
    ipv6cp_is_open[unit] = 1;
    fsm_open(f);
}


/*
 * ipv6cp_close - Close IPv6CP
 */
static void
ipv6cp_close(unit, reason)
    int unit;
    char *reason;
{
    fsm *f = &ipv6cp_fsm[unit];
    
    if (!ipv6cp_is_open[unit])
        return;
        
    ipv6cp_is_open[unit] = 0;
    fsm_close(f, reason);
}


/*
 * ipv6cp_printpkt - Print IPv6CP packet
 */
static int
ipv6cp_printpkt(p, len, printer, arg)
    u_char *p;
    int len;
    printer_func printer;
    void *arg;
{
    return 0;
}


/*
 * ipv6cp_active_pkt - Process IPv6CP packet
 */
static int
ipv6cp_active_pkt(p, len)
    u_char *p;
    int len;
{
    return 1;
}


/*
 * Protocol entry point
 */
struct protent ipv6cp_protent = {
    PPP_IPV6CP,
    ipv6cp_init,
    ipv6cp_input,
    ipv6cp_protrej_unit,
    ipv6cp_lowerup,
    ipv6cp_lowerdown,
    ipv6cp_open,
    ipv6cp_close,
    ipv6cp_printpkt,
    NULL,
    1,
    "IPV6CP",
    "IPv6",
    NULL,
    NULL,
    NULL,
    ipv6cp_active_pkt
};
