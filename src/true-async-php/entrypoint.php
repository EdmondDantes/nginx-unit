<?php

use NginxUnit\HttpServer;
use NginxUnit\Request;
use NginxUnit\Response;

set_time_limit(0);

echo "Starting NginxUnit HttpServer...\n";

//
// The function, the entry point, is called from NGINX UNIT.
//
HttpServer::onRequest(static function (Request $request, Response $response) {
    // Get request info
    $method = $request->getMethod();
    $uri = $request->getUri();

    // Set response headers
    $response->setHeader('Content-Type', 'application/json');
    $response->setStatus(200);

    // Send JSON response
    $responseData = [
        'message' => 'Hello from NginxUnit TrueAsync HttpServer!',
        'method' => $method,
        'uri' => $uri,
        'timestamp' => date('Y-m-d H:i:s')
    ];

    $response->write(json_encode($responseData, JSON_PRETTY_PRINT));
    $response->end();
});

echo "Request handler registered. Starting server...\n";
