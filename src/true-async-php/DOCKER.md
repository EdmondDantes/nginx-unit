# Docker Setup for NGINX Unit with TrueAsync PHP

## Build Image

```bash
docker build -t nginx-unit-trueasync:latest .
```

### Build with custom branches

```bash
docker build \
  --build-arg PHP_BRANCH=true-async-stable \
  --build-arg TRUEASYNC_BRANCH=main \
  --build-arg NGINX_UNIT_BRANCH=true-async \
  -t nginx-unit-trueasync:latest .
```

## Run Container

### Basic run

```bash
docker run -d \
  --name unit-trueasync \
  -p 8080:8080 \
  nginx-unit-trueasync:latest
```

### Run with custom application

```bash
docker run -d \
  --name unit-trueasync \
  -p 8080:8080 \
  -v $(pwd)/my-app:/app \
  nginx-unit-trueasync:latest
```

### Run with logs

```bash
docker run -d \
  --name unit-trueasync \
  -p 8080:8080 \
  -v $(pwd)/logs:/var/log/unit \
  nginx-unit-trueasync:latest
```

## Test

```bash
curl http://localhost:8080/
```

Expected response:
```json
{
    "message": "Hello from NginxUnit TrueAsync HttpServer!",
    "method": "GET",
    "uri": "/",
    "timestamp": "2025-10-04 15:30:00"
}
```

## View Logs

```bash
docker logs -f unit-trueasync
```

## Execute Commands Inside Container

```bash
# PHP version
docker exec unit-trueasync php -v

# Unit version
docker exec unit-trueasync unitd --version

# View current configuration
docker exec unit-trueasync curl --unix-socket /var/run/unit/control.sock http://localhost/config
```

## Custom Configuration

Create your own `unit-config.json`:

```json
{
  "applications": {
    "my-php-async-app": {
      "type": "php",
      "async": true,
      "processes": 2,
      "entrypoint": "/app/entrypoint.php",
      "working_directory": "/app",
      "root": "/app"
    }
  },
  "listeners": {
    "0.0.0.0:8080": {
      "pass": "applications/my-php-async-app"
    }
  }
}
```

Apply configuration:

```bash
docker exec unit-trueasync curl -X PUT \
  --data-binary @/app/unit-config.json \
  --unix-socket /var/run/unit/control.sock \
  http://localhost/config
```

## Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  unit:
    build: .
    image: nginx-unit-trueasync:latest
    container_name: unit-trueasync
    ports:
      - "8080:8080"
    volumes:
      - ./my-app:/app
      - ./logs:/var/log/unit
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
```

Run with compose:

```bash
docker compose up -d
```

## Build Stages

The Dockerfile uses multi-stage build:

1. **Builder stage** (ubuntu:24.04)
   - Install build dependencies
   - Build libuv 1.49
   - Build curl 8.10
   - Clone and build PHP with TrueAsync extension
   - Clone and build NGINX Unit
   - Build PHP module for NGINX Unit

2. **Runtime stage** (ubuntu:24.04)
   - Install only runtime dependencies
   - Copy built binaries from builder
   - Setup user and permissions
   - Configure startup script

## Repositories Used

- PHP: https://github.com/true-async/php-src (branch: `true-async-stable`)
- TrueAsync Extension: https://github.com/true-async/php-async (branch: `main`)
- NGINX Unit: https://github.com/EdmondDantes/nginx-unit (branch: `true-async`)

## Troubleshooting

### Container exits immediately

Check logs:
```bash
docker logs unit-trueasync
```

### Configuration not loading

Verify paths in `unit-config.json` are absolute and point to `/app`.

### Permission denied errors

Ensure volumes are readable by UID/GID 999 (unit user).

### Module not found

Verify PHP module was built:
```bash
docker exec unit-trueasync ls -la /usr/local/unit/modules/
```

Should show `php.unit.so` or similar.
