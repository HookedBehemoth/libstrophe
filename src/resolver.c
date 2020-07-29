/* resolver.c
 * strophe XMPP client library -- DNS resolver
 *
 * Copyright (C) 2015 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

/** @file
 *  DNS resolver.
 */

#include "resolver.h"

void resolver_initialize(void) {}

void resolver_shutdown(void) {}

int resolver_srv_lookup_buf(xmpp_ctx_t *ctx,
                            const unsigned char *buf,
                            size_t len,
                            resolver_srv_rr_t **srv_rr_list)
{
    (void)ctx;
    (void)buf;
    (void)len;
    (void)srv_rr_list;
    return 0;
}

int resolver_srv_lookup(xmpp_ctx_t *ctx,
                        const char *service,
                        const char *proto,
                        const char *domain,
                        resolver_srv_rr_t **srv_rr_list)
{
    (void)ctx;
    (void)service;
    (void)proto;
    (void)domain;
    (void)srv_rr_list;
    return 0;
}

void resolver_srv_free(xmpp_ctx_t *ctx, resolver_srv_rr_t *srv_rr_list)
{
    (void)ctx;
    (void)srv_rr_list;
}
