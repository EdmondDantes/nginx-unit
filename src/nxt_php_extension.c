/*
 * Copyright (C) NGINX Unit PHP Extension
 *
 * This file contains PHP class definitions for NginxUnit namespace:
 * - NginxUnit\Request
 * - NginxUnit\Response
 * - NginxUnit\Server
 */

#include "php.h"
#include "SAPI.h"
#include "php_main.h"
#include "main/network_async.h"
#include "Zend/zend_async_API.h"

#include <nxt_main.h>
#include <nxt_unit.h>
#include <nxt_unit_request.h>

#include "nxt_php_extension.h"


/* PHP 8 compatibility */
#ifndef TSRMLS_CC
#define TSRMLS_CC
#define TSRMLS_DC
#define TSRMLS_D  void
#define TSRMLS_C
#endif

#if (PHP_VERSION_ID >= 70000)
#define NXT_PHP7 1
#endif
#if (PHP_VERSION_ID >= 80000)
#define NXT_PHP8 1
#endif


/* ========== Custom Object Structures ========== */

/* Request object - stores nxt_unit_request_info_t* */
typedef struct {
    nxt_unit_request_info_t  *req;
    zend_object              std;
} nxt_php_request_object;

/* Response object - stores nxt_unit_request_info_t* and response state */
typedef struct {
    nxt_unit_request_info_t  *req;
    uint8_t                  headers_sent;  /* 1 if headers already sent */
    zend_object              std;
} nxt_php_response_object;


/* ========== Class Entries ========== */

static zend_class_entry  *nxt_php_request_ce;
static zend_class_entry  *nxt_php_response_ce;
static zend_class_entry  *nxt_php_http_server_ce;


/* ========== External globals from nxt_php_sapi.c ========== */

/* Global callback for request handling */
zval  *nxt_php_request_callback = NULL;

/* ========== Object Handlers ========== */

static zend_object_handlers  nxt_php_request_handlers;
static zend_object_handlers  nxt_php_response_handlers;


/* Helper to get object from zend_object */
static inline nxt_php_request_object *
nxt_php_request_from_obj(zend_object *obj)
{
    return (nxt_php_request_object *)((char *)(obj) - XtOffsetOf(nxt_php_request_object, std));
}

static inline nxt_php_response_object *
nxt_php_response_from_obj(zend_object *obj)
{
    return (nxt_php_response_object *)((char *)(obj) - XtOffsetOf(nxt_php_response_object, std));
}


/* Create Request object */
static zend_object *
nxt_php_request_create_object(zend_class_entry *ce)
{
    nxt_php_request_object  *obj;

    obj = ecalloc(1, sizeof(nxt_php_request_object) + zend_object_properties_size(ce));

    zend_object_std_init(&obj->std, ce);
    object_properties_init(&obj->std, ce);

    obj->std.handlers = &nxt_php_request_handlers;
    obj->req = NULL;

    return &obj->std;
}

/* Create Response object */
static zend_object *
nxt_php_response_create_object(zend_class_entry *ce)
{
    nxt_php_response_object  *obj;

    obj = ecalloc(1, sizeof(nxt_php_response_object) + zend_object_properties_size(ce));

    zend_object_std_init(&obj->std, ce);
    object_properties_init(&obj->std, ce);

    obj->std.handlers = &nxt_php_response_handlers;
    obj->req = NULL;
    obj->headers_sent = 0;

    return &obj->std;
}

/* Free Request object */
static void
nxt_php_request_free_object(zend_object *object)
{
    nxt_php_request_object  *obj = nxt_php_request_from_obj(object);

    /* Don't free req - it's managed by Unit */
    obj->req = NULL;

    zend_object_std_dtor(object);
}

/* Free Response object */
static void
nxt_php_response_free_object(zend_object *object)
{
    nxt_php_response_object  *obj = nxt_php_response_from_obj(object);

    /* Don't free req - it's managed by Unit */
    obj->req = NULL;

    zend_object_std_dtor(object);
}


/* ========== PHP Method Declarations ========== */

/* NginxUnit\Request methods */
PHP_METHOD(NginxUnit_Request, getMethod);
PHP_METHOD(NginxUnit_Request, getUri);
PHP_METHOD(NginxUnit_Request, getRequestContext);
PHP_METHOD(NginxUnit_Request, getRequestContextParameters);
PHP_METHOD(NginxUnit_Request, createResponse);

/* NginxUnit\Response methods */
PHP_METHOD(NginxUnit_Response, setStatus);
PHP_METHOD(NginxUnit_Response, setHeader);
PHP_METHOD(NginxUnit_Response, write);
PHP_METHOD(NginxUnit_Response, end);

/* NginxUnit\HttpServer methods */
PHP_METHOD(NginxUnit_HttpServer, onRequest);


/* ========== Argument Info ========== */

ZEND_BEGIN_ARG_INFO_EX(arginfo_unit_request_get_method, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_unit_request_create_response, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_unit_response_set_status, 0, 0, 1)
    ZEND_ARG_INFO(0, status)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_unit_response_set_header, 0, 0, 2)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, value)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_unit_response_write, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_unit_response_end, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_unit_http_server_on_request, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

/* ========== Method Tables ========== */

static const zend_function_entry  nxt_php_request_methods[] = {
    PHP_ME(NginxUnit_Request, getMethod, arginfo_unit_request_get_method, ZEND_ACC_PUBLIC)
    PHP_ME(NginxUnit_Request, getUri, arginfo_unit_request_get_method, ZEND_ACC_PUBLIC)
    PHP_ME(NginxUnit_Request, getRequestContext, arginfo_unit_request_get_method, ZEND_ACC_PUBLIC)
    PHP_ME(NginxUnit_Request, getRequestContextParameters, arginfo_unit_request_get_method, ZEND_ACC_PUBLIC)
    PHP_ME(NginxUnit_Request, createResponse, arginfo_unit_request_create_response, ZEND_ACC_PUBLIC)
    ZEND_FE_END
};

static const zend_function_entry  nxt_php_response_methods[] = {
    PHP_ME(NginxUnit_Response, setStatus, arginfo_unit_response_set_status, ZEND_ACC_PUBLIC)
    PHP_ME(NginxUnit_Response, setHeader, arginfo_unit_response_set_header, ZEND_ACC_PUBLIC)
    PHP_ME(NginxUnit_Response, write, arginfo_unit_response_write, ZEND_ACC_PUBLIC)
    PHP_ME(NginxUnit_Response, end, arginfo_unit_response_end, ZEND_ACC_PUBLIC)
    ZEND_FE_END
};

static const zend_function_entry  nxt_php_http_server_methods[] = {
    PHP_ME(NginxUnit_HttpServer, onRequest, arginfo_unit_http_server_on_request, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    ZEND_FE_END
};


/* ========== Class Registration ========== */

nxt_int_t
nxt_php_extension_init(void)
{
    zend_class_entry  ce;


    /* Register NginxUnit\Request class */
    INIT_CLASS_ENTRY(ce, "NginxUnit\\Request", nxt_php_request_methods);
    nxt_php_request_ce = zend_register_internal_class(&ce TSRMLS_CC);
    nxt_php_request_ce->create_object = nxt_php_request_create_object;

    memcpy(&nxt_php_request_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    nxt_php_request_handlers.offset = XtOffsetOf(nxt_php_request_object, std);
    nxt_php_request_handlers.free_obj = nxt_php_request_free_object;

    /* Register NginxUnit\Response class */
    INIT_CLASS_ENTRY(ce, "NginxUnit\\Response", nxt_php_response_methods);
    nxt_php_response_ce = zend_register_internal_class(&ce TSRMLS_CC);
    nxt_php_response_ce->create_object = nxt_php_response_create_object;

    memcpy(&nxt_php_response_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    nxt_php_response_handlers.offset = XtOffsetOf(nxt_php_response_object, std);
    nxt_php_response_handlers.free_obj = nxt_php_response_free_object;

    /* Register NginxUnit\HttpServer class */
    INIT_CLASS_ENTRY(ce, "NginxUnit\\HttpServer", nxt_php_http_server_methods);
    nxt_php_http_server_ce = zend_register_internal_class(&ce TSRMLS_CC);

    return NXT_OK;
}


/* ========== Request Methods Implementation ========== */

PHP_METHOD(NginxUnit_Request, getMethod)
{
    nxt_php_request_object   *obj;
    nxt_unit_request_t       *r;

    obj = nxt_php_request_from_obj(Z_OBJ_P(getThis()));

    if (obj->req == NULL) {
        RETURN_NULL();
    }

    r = obj->req->request;

    RETURN_STRINGL((char *)nxt_unit_sptr_get(&r->method), r->method_length);
}

PHP_METHOD(NginxUnit_Request, getUri)
{
    nxt_php_request_object   *obj;
    nxt_unit_request_t       *r;

    obj = nxt_php_request_from_obj(Z_OBJ_P(getThis()));

    if (obj->req == NULL) {
        RETURN_NULL();
    }

    r = obj->req->request;

    RETURN_STRINGL((char *)nxt_unit_sptr_get(&r->target), r->target_length);
}

PHP_METHOD(NginxUnit_Request, getRequestContext)
{
    /* TODO: Implement if needed */
    RETURN_NULL();
}

PHP_METHOD(NginxUnit_Request, getRequestContextParameters)
{
    /* TODO: Implement if needed */
    RETURN_NULL();
}

PHP_METHOD(NginxUnit_Request, createResponse)
{
    nxt_php_request_object   *req_obj;
    nxt_php_response_object  *resp_obj;

    req_obj = nxt_php_request_from_obj(Z_OBJ_P(getThis()));

    if (req_obj->req == NULL) {
        zend_throw_error(NULL, "Request object has no associated Unit request");
        RETURN_NULL();
    }

    /* Create Response object and link it to the same request */
    object_init_ex(return_value, nxt_php_response_ce);
    resp_obj = nxt_php_response_from_obj(Z_OBJ_P(return_value));
    resp_obj->req = req_obj->req;
    resp_obj->headers_sent = 0;
}


/* ========== Response Methods Implementation ========== */

PHP_METHOD(NginxUnit_Response, setStatus)
{
    nxt_php_response_object  *obj;
    zend_long                status;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &status) == FAILURE) {
        return;
    }

    obj = nxt_php_response_from_obj(Z_OBJ_P(getThis()));

    if (obj->req == NULL) {
        zend_throw_error(NULL, "Response object has no associated Unit request");
        RETURN_FALSE;
    }

    if (obj->headers_sent) {
        zend_throw_error(NULL, "Headers already sent");
        RETURN_FALSE;
    }

    /* Initialize response with status code */
    if (nxt_unit_response_init(obj->req, status, 0, 0) != NXT_UNIT_OK) {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_METHOD(NginxUnit_Response, setHeader)
{
    nxt_php_response_object  *obj;
    char                     *name, *value;
    size_t                   name_len, value_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &name, &name_len, &value, &value_len) == FAILURE) {
        return;
    }

    obj = nxt_php_response_from_obj(Z_OBJ_P(getThis()));

    if (obj->req == NULL) {
        zend_throw_error(NULL, "Response object has no associated Unit request");
        RETURN_FALSE;
    }

    if (obj->headers_sent) {
        zend_throw_error(NULL, "Headers already sent");
        RETURN_FALSE;
    }

    /* Add header field */
    if (nxt_unit_response_add_field(obj->req, name, name_len, value, value_len) != NXT_UNIT_OK) {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_METHOD(NginxUnit_Response, write)
{
    nxt_php_response_object  *obj;
    zend_string              *data_str;
    ssize_t                  res;
    size_t                   sent;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(data_str)
    ZEND_PARSE_PARAMETERS_END();

    obj = nxt_php_response_from_obj(Z_OBJ_P(getThis()));

    if (obj->req == NULL) {
        zend_throw_error(NULL, "Response object has no associated Unit request");
        RETURN_FALSE;
    }

    /* Send headers if not sent yet */
    if (!obj->headers_sent) {
        if (nxt_unit_response_send(obj->req) != NXT_UNIT_OK) {
            RETURN_FALSE;
        }
        obj->headers_sent = 1;
    }

    /* Try to write response body immediately */
    res = nxt_unit_response_write_nb(obj->req,
                                     ZSTR_VAL(data_str),
                                     ZSTR_LEN(data_str),
                                     0);

    if (res < 0) {
        /* Error occurred */
        RETURN_FALSE;
    }

    sent = (size_t) res;

    if (sent < ZSTR_LEN(data_str)) {
        /* Not everything sent - add to drain_queue for async completion */
        if (nxt_php_drain_queue_add(nxt_php_unit_ctx, obj->req, data_str, sent) == NULL) {
            /* Failed to queue - but we already sent partial data, so return true */
            /* The partial data was sent successfully */
        }
        /* Data will be sent asynchronously via shm_ack_handler */
    }

    RETURN_TRUE;
}

PHP_METHOD(NginxUnit_Response, end)
{
    nxt_php_response_object  *obj;

    obj = nxt_php_response_from_obj(Z_OBJ_P(getThis()));

    if (obj->req == NULL) {
        zend_throw_error(NULL, "Response object has no associated Unit request");
        RETURN_FALSE;
    }

    /* Send headers if not sent yet */
    if (!obj->headers_sent) {
        if (nxt_unit_response_send(obj->req) != NXT_UNIT_OK) {
            RETURN_FALSE;
        }
        obj->headers_sent = 1;
    }

    /* Mark request as done */
    nxt_unit_request_done(obj->req, NXT_UNIT_OK);

    RETURN_TRUE;
}


/* ========== HttpServer Methods Implementation ========== */

/**
 * This method defines a callback handler that will be invoked on each call.
 **/
PHP_METHOD(NginxUnit_HttpServer, onRequest)
{
    zval  *callback;


    if (zend_parse_parameters(ZEND_NUM_ARGS(), "z", &callback) == FAILURE) {
        RETURN_FALSE;
    }

    /* Validate callback */
    if (!zend_is_callable(callback, 0, NULL)) {
        zend_throw_error(NULL, "Argument must be a valid callback");
        RETURN_FALSE;
    }

    /* Store callback globally */
    if (nxt_php_request_callback != NULL) {
        zval_ptr_dtor(nxt_php_request_callback);
        efree(nxt_php_request_callback);
    }

    nxt_php_request_callback = emalloc(sizeof(zval));
    ZVAL_COPY(nxt_php_request_callback, callback);


    RETURN_TRUE;
}

/* ========== Helper Functions ========== */

/* Function to create HttpRequest object from nxt_unit_request_info_t */
static int
nxt_php_create_request_object(zval *return_value, nxt_unit_request_info_t *req)
{
    nxt_php_request_object  *obj;

    object_init_ex(return_value, nxt_php_request_ce);
    obj = nxt_php_request_from_obj(Z_OBJ_P(return_value));
    obj->req = req;

    return SUCCESS;
}

/* Function to create HttpResponse object from nxt_unit_request_info_t */
static int
nxt_php_create_response_object(zval *return_value, nxt_unit_request_info_t *req)
{
    nxt_php_response_object  *obj;

    object_init_ex(return_value, nxt_php_response_ce);
    obj = nxt_php_response_from_obj(Z_OBJ_P(return_value));
    obj->req = req;
    obj->headers_sent = 0;

    /* Initialize empty response */
    if (nxt_unit_response_init(req, 200, 16, 2048) != NXT_UNIT_OK) {
        return FAILURE;
    }

    return SUCCESS;
}

/*
 * Coroutine entry point - called from request_handler for each request
 * Retrieves request from coroutine->extended_data and processes it
 */
void
nxt_php_request_coroutine_entry(void)
{
    zend_coroutine_t         *coroutine;
    nxt_unit_request_info_t  *req;
    zval                     request_obj, response_obj, params[2], retval;

    /* Get current coroutine */
    coroutine = ZEND_ASYNC_CURRENT_COROUTINE;
    if (coroutine == NULL) {
        /* This should never happen - entry is called from coroutine context */
        return;
    }

    /* Get request from coroutine's extended_data */
    req = (nxt_unit_request_info_t *) coroutine->extended_data;
    if (req == NULL) {
        /* No request data - nothing to do */
        return;
    }

    if (nxt_php_request_callback == NULL) {
        nxt_unit_req_alert(req, "No request callback registered");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);
        return;
    }

    /* Create Request object */
    if (nxt_php_create_request_object(&request_obj, req) != SUCCESS) {
        nxt_unit_req_alert(req, "Failed to create Request object");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);
        return;
    }

    /* Create Response object */
    if (nxt_php_create_response_object(&response_obj, req) != SUCCESS) {
        nxt_unit_req_alert(req, "Failed to create Response object");
        zval_ptr_dtor(&request_obj);
        nxt_unit_request_done(req, NXT_UNIT_ERROR);
        return;
    }

    /* Prepare parameters */
    params[0] = request_obj;
    params[1] = response_obj;

    /* Call user callback */
    if (call_user_function(NULL, NULL, nxt_php_request_callback, &retval, 2, params) != SUCCESS) {
        nxt_unit_req_alert(req, "Failed to call request callback");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);
    }

    /* Cleanup */
    zval_ptr_dtor(&retval);
    zval_ptr_dtor(&request_obj);
    zval_ptr_dtor(&response_obj);
}
