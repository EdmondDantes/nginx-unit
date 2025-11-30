/*
 * Copyright (C) NGINX Unit PHP Superglobals Support
 *
 * This file provides integration between NGINX Unit requests
 * and PHP TrueAsync Scope superglobals.
 */

#include "php.h"
#include "SAPI.h"
#include "php_main.h"
#include "php_variables.h"
#include "Zend/zend_async_API.h"

#include <nxt_main.h>
#include <nxt_unit.h>
#include <nxt_unit_request.h>

#include "nxt_php_superglobals.h"


/* Forward declarations of Unit's existing types and functions */
typedef struct nxt_php_run_ctx_s nxt_php_run_ctx_t;

struct nxt_php_run_ctx_s {
    nxt_unit_request_info_t  *req;
    nxt_str_t                *root;
    nxt_str_t                *index;
    nxt_str_t                script_name;
    nxt_str_t                script_filename;
    nxt_str_t                script_dirname;
    nxt_str_t                path_info;
    char                     *cookie;
    uint8_t                  chdir;
};

extern void nxt_php_register_variables(zval *track_vars_array);


/**
 * Initialize empty superglobals arrays in a Scope
 * This creates $_GET, $_POST, $_COOKIE, $_SERVER, $_ENV, $_FILES, $_REQUEST
 * as empty arrays in scope->superglobals
 */
void
nxt_php_scope_init_superglobals(zend_async_scope_t *scope)
{
    zval empty_array;

    /* If already initialized - nothing to do */
    if (scope->superglobals != NULL) {
        return;
    }

    /* Allocate and initialize HashTable */
    ALLOC_HASHTABLE(scope->superglobals);
    zend_hash_init(scope->superglobals, 8, NULL, ZVAL_PTR_DTOR, 0);

    /* Initialize empty arrays for all superglobals */

    /* $_GET */
    array_init(&empty_array);
    zend_hash_str_add(scope->superglobals, "_GET", sizeof("_GET") - 1, &empty_array);

    /* $_POST */
    array_init(&empty_array);
    zend_hash_str_add(scope->superglobals, "_POST", sizeof("_POST") - 1, &empty_array);

    /* $_COOKIE */
    array_init(&empty_array);
    zend_hash_str_add(scope->superglobals, "_COOKIE", sizeof("_COOKIE") - 1, &empty_array);

    /* $_SERVER */
    array_init(&empty_array);
    zend_hash_str_add(scope->superglobals, "_SERVER", sizeof("_SERVER") - 1, &empty_array);

    /* $_ENV */
    array_init(&empty_array);
    zend_hash_str_add(scope->superglobals, "_ENV", sizeof("_ENV") - 1, &empty_array);

    /* $_FILES */
    array_init(&empty_array);
    zend_hash_str_add(scope->superglobals, "_FILES", sizeof("_FILES") - 1, &empty_array);

    /* $_REQUEST */
    array_init(&empty_array);
    zend_hash_str_add(scope->superglobals, "_REQUEST", sizeof("_REQUEST") - 1, &empty_array);
}


/**
 * Populate superglobals with data from NGINX Unit request
 *
 * This function reuses NGINX Unit's existing code by temporarily
 * substituting PG(http_globals) to point to scope->superglobals,
 * then calling standard PHP functions to populate them.
 *
 * IMPORTANT: SG(server_context) must be set before calling this function!
 */
void
nxt_php_scope_populate_superglobals(zend_async_scope_t *scope)
{
    zval *server_array;
    zval saved_http_globals[6];
    nxt_php_run_ctx_t *ctx;
    nxt_unit_request_t *r;
    int i;

    /* Ensure superglobals are initialized */
    if (scope->superglobals == NULL) {
        nxt_php_scope_init_superglobals(scope);
    }

    /* Get context from SG(server_context) */
    ctx = SG(server_context);
    if (ctx == NULL || ctx->req == NULL) {
        return;
    }

    r = ctx->req->request;

    /* Save original PG(http_globals) */
    for (i = 0; i < 6; i++) {
        saved_http_globals[i] = PG(http_globals)[i];
    }

    /* Temporarily replace PG(http_globals) with our scope superglobals */
    PG(http_globals)[0] = *zend_hash_str_find(scope->superglobals, "_POST", sizeof("_POST") - 1);      /* TRACK_VARS_POST */
    PG(http_globals)[1] = *zend_hash_str_find(scope->superglobals, "_GET", sizeof("_GET") - 1);        /* TRACK_VARS_GET */
    PG(http_globals)[2] = *zend_hash_str_find(scope->superglobals, "_COOKIE", sizeof("_COOKIE") - 1);  /* TRACK_VARS_COOKIE */
    PG(http_globals)[3] = *zend_hash_str_find(scope->superglobals, "_SERVER", sizeof("_SERVER") - 1);  /* TRACK_VARS_SERVER */
    PG(http_globals)[4] = *zend_hash_str_find(scope->superglobals, "_ENV", sizeof("_ENV") - 1);        /* TRACK_VARS_ENV */
    PG(http_globals)[5] = *zend_hash_str_find(scope->superglobals, "_FILES", sizeof("_FILES") - 1);    /* TRACK_VARS_FILES */

    /* Now call standard PHP functions - they will write to our arrays! */

    /* 1. Fill $_SERVER using existing Unit function */
    server_array = &PG(http_globals)[3];
    nxt_php_register_variables(server_array);

    /* 2. Parse query string into $_GET */
    if (r->query_length > 0) {
        char *query = estrndup((char *)nxt_unit_sptr_get(&r->query), r->query_length);
        sapi_module.treat_data(PARSE_STRING, query, NULL);
        /* treat_data frees query */
    }

    /* 3. Parse cookies into $_COOKIE */
    if (ctx->cookie != NULL) {
        char *cookie = estrdup(ctx->cookie);
        sapi_module.treat_data(PARSE_COOKIE, cookie, NULL);
        /* treat_data frees cookie */
    }

    /* 4. Parse POST data into $_POST (if POST request) */
    if (SG(request_info).request_method && !strcasecmp(SG(request_info).request_method, "POST")) {
        sapi_module.treat_data(PARSE_POST, NULL, NULL);
    }

    /* Restore original PG(http_globals) */
    for (i = 0; i < 6; i++) {
        PG(http_globals)[i] = saved_http_globals[i];
    }
}
