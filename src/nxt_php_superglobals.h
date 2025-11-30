/*
 * Copyright (C) Edmond
 */

#ifndef _NXT_PHP_SUPERGLOBALS_H_INCLUDED_
#define _NXT_PHP_SUPERGLOBALS_H_INCLUDED_

#include "php.h"
#include "Zend/zend_async_API.h"


/**
 * Initialize empty superglobals arrays in a Scope
 * This creates $_GET, $_POST, $_COOKIE, $_SERVER, $_ENV, $_FILES, $_REQUEST
 * as empty arrays in scope->superglobals
 */
void nxt_php_scope_init_superglobals(zend_async_scope_t *scope);


/**
 * Populate superglobals with data from NGINX Unit request
 *
 * IMPORTANT: SG(server_context) must be set before calling this function!
 *
 * This fills $_SERVER by calling existing Unit's nxt_php_register_variables().
 * $_GET, $_POST, $_COOKIE, $_FILES will be populated automatically by PHP
 * when the script accesses these variables.
 */
void nxt_php_scope_populate_superglobals(zend_async_scope_t *scope);


#endif /* _NXT_PHP_SUPERGLOBALS_H_INCLUDED_ */
