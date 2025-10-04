/*
 * Copyright (C) NGINX Unit PHP Extension
 */

#ifndef _NXT_PHP_EXTENSION_H_INCLUDED_
#define _NXT_PHP_EXTENSION_H_INCLUDED_

#include "php.h"
#include "SAPI.h"

#include <nxt_unit.h>
#include "Zend/zend_async_API.h"


/* Register all NginxUnit\ PHP classes */
nxt_int_t nxt_php_extension_init(void);

/* Coroutine entry point - retrieves request from coroutine->extended_data */
void nxt_php_request_coroutine_entry(void);

/* Pending write entry for drain_queue (forward declaration) */
typedef struct nxt_php_pending_write_s nxt_php_pending_write_t;

/* Function to add pending write to drain_queue */
nxt_php_pending_write_t *nxt_php_drain_queue_add(nxt_unit_ctx_t *ctx,
                                                  nxt_unit_request_info_t *req,
                                                  zend_string *str,
                                                  size_t offset);

/* Globals exported from nxt_php_sapi.c */
extern nxt_unit_ctx_t           *nxt_php_unit_ctx;
extern nxt_unit_port_t          *nxt_php_read_port;
extern nxt_unit_port_t          *nxt_php_shared_port;
extern zend_async_poll_event_t  *nxt_php_socket_poll_event;


#endif /* _NXT_PHP_EXTENSION_H_INCLUDED_ */
