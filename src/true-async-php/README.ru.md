# NGINX Unit TrueAsync PHP Integration

Асинхронная интеграция PHP с NGINX Unit на основе корутин PHP и TrueAsync SAPI.

## Особенности интеграции

### Архитектура

Интеграция работает на трёх уровнях:

1. **C-уровень (nxt_php_sapi.c, nxt_php_extension.c)**
   - Регистрация TrueAsync SAPI в PHP
   - Создание корутин для каждого запроса
   - Управление событийным циклом через `nxt_unit_run()`
   - Неблокирующая отправка данных через `nxt_unit_response_write_nb()`

2. **PHP Extension (NginxUnit namespace)**
   - `NginxUnit\Request` - объект входящего запроса
   - `NginxUnit\Response` - объект ответа с неблокирующей отправкой
   - `NginxUnit\HttpServer::onRequest()` - регистрация обработчика

3. **Пользовательский код (entrypoint.php)**
   - Регистрация обработчика через `HttpServer::onRequest()`
   - Работа с Request/Response API
   - Полностью асинхронное выполнение

### Как работает запрос

```
HTTP Request → NGINX Unit → nxt_php_request_handler()
                                ↓
                    Создание корутины (zend_async_coroutine_create)
                                ↓
                    nxt_php_request_coroutine_entry()
                                ↓
                    Создание Request/Response объектов
                                ↓
                    Вызов callback из entrypoint.php
                                ↓
                    response->write() → nxt_unit_response_write_nb()
                                ↓
                    response->end() → nxt_unit_request_done()
```

### Неблокирующий I/O

При вызове `$response->write($data)`:

1. Данные отправляются через `nxt_unit_response_write_nb()`
2. Если буфер заполнен — остаток добавляется в `drain_queue`
3. При освобождении буфера срабатывает `shm_ack_handler`
4. Данные дописываются асинхронно без блокировки корутины

## Конфигурация

### unit-config.json

```json
{
  "applications": {
    "my-php-async-app": {
      "type": "php",
      "async": true,              // Включает TrueAsync режим
      "processes": 2,              // Количество воркеров
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

**Важно**: `"async": true` активирует TrueAsync SAPI вместо стандартного PHP SAPI.

### Загрузка конфигурации

```bash
curl -X PUT --data-binary @unit-config.json \
  --unix-socket /tmp/unit/control.unit.sock \
  http://localhost/config
```

## entrypoint.php

### Базовая структура

```php
<?php

use NginxUnit\HttpServer;
use NginxUnit\Request;
use NginxUnit\Response;

set_time_limit(0);

// Регистрация обработчика запросов
HttpServer::onRequest(static function (Request $request, Response $response) {
    // Получение данных запроса
    $method = $request->getMethod();
    $uri = $request->getUri();

    // Установка заголовков
    $response->setHeader('Content-Type', 'application/json');
    $response->setStatus(200);

    // Отправка данных (неблокирующая)
    $response->write(json_encode([
        'message' => 'Hello from TrueAsync!',
        'method' => $method,
        'uri' => $uri
    ]));

    // Завершение ответа
    $response->end();
});
```

### API Reference

#### Request

- `getMethod(): string` - HTTP метод (GET, POST, etc.)
- `getUri(): string` - URI запроса
- `getRequestContext(): ?mixed` - Контекст запроса (TODO)
- `getRequestContextParameters(): ?mixed` - Параметры контекста (TODO)
- `createResponse(): Response` - Создать Response объект (обычно не нужен)

#### Response

- `setStatus(int $code): bool` - Установить HTTP статус
- `setHeader(string $name, string $value): bool` - Добавить заголовок
- `write(string $data): bool` - Отправить данные (неблокирующая операция)
- `end(): bool` - Завершить ответ и освободить ресурсы

**Важно**:
- `setStatus()` и `setHeader()` нужно вызывать ДО первого `write()`
- После `write()` заголовки уже отправлены
- `end()` обязателен для завершения запроса

### Жизненный цикл

```php
HttpServer::onRequest(function (Request $req, Response $resp) {
    // 1. Заголовки можно менять
    $resp->setStatus(200);
    $resp->setHeader('Content-Type', 'text/plain');

    // 2. Первый write() отправляет заголовки
    $resp->write('Hello ');

    // 3. Заголовки уже нельзя менять
    // $resp->setHeader() → Error!

    // 4. Можно дописывать данные
    $resp->write('World!');

    // 5. Завершение запроса (обязательно!)
    $resp->end();
});
```

## Запуск и тестирование

### Запуск NGINX Unit

```bash
./build/sbin/unitd \
  --no-daemon \
  --log /tmp/unit/unit.log \
  --state /tmp/unit \
  --control unix:/tmp/unit/control.unit.sock \
  --pid /tmp/unit/unit.pid \
  --modules ./build/lib/unit/modules
```

**Важно**: параметр `--modules` обязателен для загрузки PHP модуля!

### Просмотр логов

```bash
tail -f /tmp/unit/unit.log
```

### Тестирование

```bash
curl http://127.0.0.1:8080/
```

Ответ:
```json
{
    "message": "Hello from NginxUnit HttpServer!",
    "method": "GET",
    "uri": "/",
    "timestamp": "2025-10-04 15:30:00"
}
```

### Нагрузочное тестирование

```bash
wrk -t4 -c100 -d30s http://127.0.0.1:8080/
```

## Отладка

### GDB

```bash
gdb ./build/sbin/unitd
(gdb) set follow-fork-mode child
(gdb) run --no-daemon --log /tmp/unit/unit.log ...
```

### Точки останова

```gdb
break nxt_php_request_handler
break nxt_php_request_coroutine_entry
break nxt_unit_response_write_nb
```

### Полезные команды

```bash
# Остановить все процессы
pkill -9 unitd

# Проверить сокет
ls -la /tmp/unit/control.unit.sock

# Получить текущую конфигурацию
curl --unix-socket /tmp/unit/control.unit.sock http://localhost/config
```

## Внутренняя реализация

### Инициализация

1. `nxt_php_extension_init()` регистрирует классы в namespace `NginxUnit`
2. `entrypoint.php` загружается при старте воркера
3. `HttpServer::onRequest()` сохраняет callback в `nxt_php_request_callback`

### Обработка запроса

1. NGINX Unit вызывает `nxt_php_request_handler(req)`
2. Создаётся корутина: `zend_async_coroutine_create(nxt_php_request_coroutine_entry)`
3. В `req` сохраняется указатель на корутину
4. Корутина добавляется в очередь активации
5. Управление возвращается в событийный цикл `nxt_unit_run()`

### Активация корутины

1. Событийный цикл вызывает `nxt_unit_response_buf_alloc` callback
2. Callback активирует корутину через `zend_async_coroutine_activate()`
3. Выполняется `nxt_php_request_coroutine_entry()`
4. Создаются PHP объекты Request/Response
5. Вызывается пользовательский callback
6. После `response->end()` корутина завершается

### Асинхронная отправка

1. `response->write()` → `nxt_unit_response_write_nb()`
2. Если отправлено не всё — остаток в `drain_queue`
3. При освобождении буфера → `shm_ack_handler()`
4. `shm_ack_handler` дописывает данные и вызывает `end()` при необходимости

## Ограничения

- Корутины не поддерживают стандартные PHP async функции (async/await)
- TrueAsync SAPI несовместим с традиционным PHP-FPM кодом
- Все операции I/O должны идти через NGINX Unit API
- `response->end()` обязателен — иначе утечка ресурсов

## TODO

- Реализовать `Request::getRequestContext()`
- Добавить поддержку заголовков запроса
- Добавить POST body parsing
- WebSocket поддержку
- Streaming responses
