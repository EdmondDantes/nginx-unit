# NGINX Unit TrueAsync PHP Integration

Asynchronous PHP integration with NGINX Unit based on PHP coroutines and TrueAsync SAPI.

## Integration Features

### Architecture

The integration works on three levels:

1. **C-level (nxt_php_sapi.c, nxt_php_extension.c)**
   - TrueAsync SAPI registration in PHP
   - Coroutine creation for each request
   - Event loop management via `nxt_unit_run()`
   - Non-blocking data transmission via `nxt_unit_response_write_nb()`

2. **PHP Extension (NginxUnit namespace)**
   - `NginxUnit\Request` - incoming request object
   - `NginxUnit\Response` - response object with non-blocking send
   - `NginxUnit\HttpServer::onRequest()` - handler registration

3. **User code (entrypoint.php)**
   - Handler registration via `HttpServer::onRequest()`
   - Working with Request/Response API
   - Fully asynchronous execution

### Request Flow

```
HTTP Request → NGINX Unit → nxt_php_request_handler()
                                ↓
                    Create coroutine (zend_async_coroutine_create)
                                ↓
                    nxt_php_request_coroutine_entry()
                                ↓
                    Create Request/Response objects
                                ↓
                    Call callback from entrypoint.php
                                ↓
                    response->write() → nxt_unit_response_write_nb()
                                ↓
                    response->end() → nxt_unit_request_done()
```

### Non-blocking I/O

When calling `$response->write($data)`:

1. Data is sent via `nxt_unit_response_write_nb()`
2. If buffer is full — remainder is added to `drain_queue`
3. When buffer is freed — `shm_ack_handler` is triggered
4. Data is written asynchronously without blocking the coroutine

## Configuration

### unit-config.json

```json
{
  "applications": {
    "my-php-async-app": {
      "type": "php",
      "async": true,              // Enable TrueAsync mode
      "processes": 2,              // Number of workers
      "entrypoint": "/path/to/entrypoint.php",
      "working_directory": "/path/to/",
      "root": "/path/to/"
    }
  },
  "listeners": {
    "127.0.0.1:8080": {
      "pass": "applications/my-php-async-app"
    }
  }
}
```

**Important**: `"async": true` activates TrueAsync SAPI instead of standard PHP SAPI.

### Loading Configuration

```bash
curl -X PUT --data-binary @unit-config.json \
  --unix-socket /tmp/unit/control.unit.sock \
  http://localhost/config
```

## entrypoint.php

### Basic Structure

```php
<?php

use NginxUnit\HttpServer;
use NginxUnit\Request;
use NginxUnit\Response;

set_time_limit(0);

// Register request handler
HttpServer::onRequest(static function (Request $request, Response $response) {
    // Get request data
    $method = $request->getMethod();
    $uri = $request->getUri();

    // Set headers
    $response->setHeader('Content-Type', 'application/json');
    $response->setStatus(200);

    // Send data (non-blocking)
    $response->write(json_encode([
        'message' => 'Hello from TrueAsync!',
        'method' => $method,
        'uri' => $uri
    ]));

    // Complete response
    $response->end();
});
```

### API Reference

#### Request

- `getMethod(): string` - HTTP method (GET, POST, etc.)
- `getUri(): string` - Request URI
- `getRequestContext(): ?mixed` - Request context (TODO)
- `getRequestContextParameters(): ?mixed` - Context parameters (TODO)
- `createResponse(): Response` - Create Response object (usually not needed)

#### Response

- `setStatus(int $code): bool` - Set HTTP status
- `setHeader(string $name, string $value): bool` - Add header
- `write(string $data): bool` - Send data (non-blocking operation)
- `end(): bool` - Complete response and free resources

**Important**:
- `setStatus()` and `setHeader()` must be called BEFORE first `write()`
- After `write()` headers are already sent
- `end()` is required to complete the request

### Lifecycle

```php
HttpServer::onRequest(function (Request $req, Response $resp) {
    // 1. Headers can be modified
    $resp->setStatus(200);
    $resp->setHeader('Content-Type', 'text/plain');

    // 2. First write() sends headers
    $resp->write('Hello ');

    // 3. Headers can no longer be modified
    // $resp->setHeader() → Error!

    // 4. Can continue writing data
    $resp->write('World!');

    // 5. Complete request (required!)
    $resp->end();
});
```

## Running and Testing

### Starting NGINX Unit

```bash
./build/sbin/unitd \
  --no-daemon \
  --log /tmp/unit/unit.log \
  --state /tmp/unit \
  --control unix:/tmp/unit/control.unit.sock \
  --pid /tmp/unit/unit.pid \
  --modules ./build/lib/unit/modules
```

**Important**: `--modules` parameter is required to load the PHP module!

### Viewing Logs

```bash
tail -f /tmp/unit/unit.log
```

### Testing

```bash
curl http://127.0.0.1:8080/
```

Response:
```json
{
    "message": "Hello from NginxUnit TrueAsync HttpServer!",
    "method": "GET",
    "uri": "/",
    "timestamp": "2025-10-04 15:30:00"
}
```

### Load Testing

```bash
wrk -t4 -c100 -d30s http://127.0.0.1:8080/
```

## Debugging

### GDB

```bash
gdb ./build/sbin/unitd
(gdb) set follow-fork-mode child
(gdb) run --no-daemon --log /tmp/unit/unit.log ...
```

### Breakpoints

```gdb
break nxt_php_request_handler
break nxt_php_request_coroutine_entry
break nxt_unit_response_write_nb
```

### Useful Commands

```bash
# Stop all processes
pkill -9 unitd

# Check socket
ls -la /tmp/unit/control.unit.sock

# Get current configuration
curl --unix-socket /tmp/unit/control.unit.sock http://localhost/config
```

## Internal Implementation

### Initialization

1. `nxt_php_extension_init()` registers classes in `NginxUnit` namespace
2. `entrypoint.php` is loaded on worker startup
3. `HttpServer::onRequest()` stores callback in `nxt_php_request_callback`

### Request Processing

1. NGINX Unit calls `nxt_php_request_handler(req)`
2. Coroutine is created: `zend_async_coroutine_create(nxt_php_request_coroutine_entry)`
3. Coroutine pointer is saved in `req`
4. Coroutine is added to activation queue
5. Control returns to event loop `nxt_unit_run()`

### Coroutine Activation

1. Event loop calls `nxt_unit_response_buf_alloc` callback
2. Callback activates coroutine via `zend_async_coroutine_activate()`
3. `nxt_php_request_coroutine_entry()` is executed
4. PHP Request/Response objects are created
5. User callback is invoked
6. After `response->end()` coroutine completes

### Asynchronous Send

1. `response->write()` → `nxt_unit_response_write_nb()`
2. If not everything sent — remainder goes to `drain_queue`
3. When buffer freed → `shm_ack_handler()`
4. `shm_ack_handler` writes remaining data and calls `end()` if needed

## Limitations

- Coroutines don't support standard PHP async functions (async/await)
- TrueAsync SAPI is incompatible with traditional PHP-FPM code
- All I/O operations must go through NGINX Unit API
- `response->end()` is required — otherwise resource leak

## TODO

- Implement `Request::getRequestContext()`
- Add request headers support
- Add POST body parsing
- WebSocket support
- Streaming responses
