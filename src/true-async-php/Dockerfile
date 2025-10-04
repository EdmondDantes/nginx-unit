# ===== NGINX Unit with TrueAsync PHP (Linux x64 ZTS Release) =====
# Multi-stage build: builder + runtime

# ---------- BUILDER STAGE ----------
FROM ubuntu:24.04 AS builder

ARG PHP_BRANCH=true-async-stable
ARG TRUEASYNC_BRANCH=main
ARG NGINX_UNIT_BRANCH=true-async

# ---------- 1. System toolchain & libraries ----------
RUN apt-get update && apt-get install -y \
    autoconf bison build-essential curl re2c git \
    cmake ninja-build wget dos2unix \
    libxml2-dev libssl-dev pkg-config libargon2-dev \
    libcurl4-openssl-dev libedit-dev libreadline-dev \
    libsodium-dev libsqlite3-dev libonig-dev libzip-dev \
    libpng-dev libjpeg-dev libwebp-dev libfreetype6-dev \
    libgmp-dev libldap2-dev libsasl2-dev libpq-dev \
    libmysqlclient-dev libbz2-dev libenchant-2-dev \
    libffi-dev libgdbm-dev liblmdb-dev libsnmp-dev \
    libtidy-dev libxslt1-dev libicu-dev libpsl-dev \
    libpcre2-dev

# ---------- 2. libuv 1.49 ----------
RUN wget -q https://github.com/libuv/libuv/archive/v1.49.0.tar.gz \
 && tar -xf v1.49.0.tar.gz \
 && cd libuv-1.49.0 && mkdir build && cd build \
 && cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
 && ninja && ninja install && ldconfig \
 && cd / && rm -rf libuv*

# ---------- 3. curl 8.10 ----------
RUN wget -q https://github.com/curl/curl/releases/download/curl-8_10_1/curl-8.10.1.tar.gz \
 && tar -xf curl-8.10.1.tar.gz \
 && cd curl-8.10.1 \
 && ./configure --prefix=/usr/local --with-openssl --enable-shared --disable-static \
 && make -j$(nproc) && make install && ldconfig \
 && cd / && rm -rf curl*

# ---------- 4. Clone repositories ----------
# Clone PHP with TrueAsync patches
RUN git clone --depth=1 --branch=${PHP_BRANCH} https://github.com/true-async/php-src /usr/src/php-src

# Clone TrueAsync extension
RUN git clone --depth=1 --branch=${TRUEASYNC_BRANCH} https://github.com/true-async/php-async /usr/src/php-async

# Clone NGINX Unit with TrueAsync support
RUN git clone --depth=1 --branch=${NGINX_UNIT_BRANCH} https://github.com/EdmondDantes/nginx-unit /usr/src/nginx-unit

# ---------- 5. Copy async extension into PHP source ----------
RUN mkdir -p /usr/src/php-src/ext/async \
 && cp -r /usr/src/php-async/* /usr/src/php-src/ext/async/

# ---------- 5.1. Fix Windows line endings ----------
RUN dos2unix /usr/src/php-src/ext/async/config.m4 || true

# ---------- 6. Configure & build PHP ----------
WORKDIR /usr/src/php-src

RUN ./buildconf --force && \
    ./configure \
        --prefix=/usr/local \
        --enable-embed \
        --with-pdo-mysql=mysqlnd --with-mysqli=mysqlnd \
        --with-pgsql --with-pdo-pgsql --with-pdo-sqlite \
        --without-pear \
        --enable-gd --with-jpeg --with-webp --with-freetype \
        --enable-exif --with-zip --with-zlib \
        --enable-soap --enable-xmlreader --with-xsl --with-tidy --with-libxml \
        --enable-sysvsem --enable-sysvshm --enable-shmop --enable-pcntl \
        --with-readline \
        --enable-mbstring --with-curl --with-gettext \
        --enable-sockets --with-bz2 --with-openssl --with-gmp \
        --enable-bcmath --enable-calendar --enable-ftp --with-enchant \
        --enable-sysvmsg --with-ffi --enable-dba --with-lmdb --with-gdbm \
        --enable-snmp --enable-intl --with-ldap --with-ldap-sasl \
        --enable-werror \
        --with-config-file-path=/etc --with-config-file-scan-dir=/etc/php.d \
        --disable-debug --enable-zts \
        --enable-async && \
    make -j$(nproc) && make install

# ---------- 7. PHP configuration ----------
RUN mkdir -p /etc/php.d && echo "opcache.enable_cli=1" > /etc/php.d/opcache.ini

# ---------- 8. Build NGINX Unit ----------
WORKDIR /usr/src/nginx-unit

# Configure and build Unit core
RUN ./configure \
        --prefix=/usr/local/unit \
        --state=/var/lib/unit \
        --control=unix:/var/run/unit/control.sock \
        --pid=/var/run/unit/unit.pid \
        --log=/var/log/unit/unit.log \
        --modules=/usr/local/unit/modules \
        --user=unit \
        --group=unit \
    && make -j$(nproc) \
    && make install

# ---------- 9. Build PHP module for NGINX Unit ----------
RUN ./configure php \
        --module=php \
        --config=/usr/local/bin/php-config \
    && make php \
    && make php-install

# ---------- 10. Copy module to correct location and verify ----------
RUN mkdir -p /usr/local/unit/modules \
    && cp /usr/local/lib/unit/modules/php.unit.so /usr/local/unit/modules/ \
    && ls -la /usr/local/unit/modules/

# ---------- RUNTIME STAGE ----------
FROM ubuntu:24.04 AS runtime

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 libssl3 libargon2-1 \
    libcurl4 libedit2 libreadline8 \
    libsodium23 libsqlite3-0 libonig5 libzip4 \
    libpng16-16 libjpeg8 libwebp7 libfreetype6 \
    libgmp10 libldap2 libsasl2-2 libpq5 \
    libmysqlclient21 libbz2-1.0 libenchant-2-2 \
    libffi8 libgdbm6 liblmdb0 libsnmp40 \
    libtidy5deb1 libxslt1.1 libicu74 libpsl5 \
    libpcre2-8-0 \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Create unit user and group with fixed UID/GID
RUN groupadd -r -g 999 unit && useradd -r -g unit -u 999 unit

# Copy built PHP and libraries from builder
COPY --from=builder /usr/local /usr/local
COPY --from=builder /etc/php.d /etc/php.d

# Create runtime directories with proper permissions
RUN mkdir -p /var/run/unit /var/lib/unit /var/log/unit /app \
    && chown -R unit:unit /var/run/unit /var/lib/unit /var/log/unit /app

# Update library cache
RUN ldconfig

# Set PATH
ENV PATH="/usr/local/bin:/usr/local/sbin:/usr/local/unit/sbin:$PATH"

# Verify installations
RUN php -v && /usr/local/unit/sbin/unitd --version

# Verify PHP module exists
RUN ls -la /usr/local/unit/modules/ && \
    test -f /usr/local/unit/modules/php.unit.so || \
    (echo "ERROR: PHP module not found!" && exit 1)

# Copy example application
COPY --from=builder /usr/src/nginx-unit/src/true-async-php/entrypoint.php /app/entrypoint.php
COPY --from=builder /usr/src/nginx-unit/src/true-async-php/unit-config.json /app/unit-config.json.template

# Update config template with correct paths
RUN sed 's|/home/edmond/nginx-unit/src/true-async-php|/app|g' /app/unit-config.json.template > /app/unit-config.json \
    && rm /app/unit-config.json.template \
    && chown unit:unit /app/unit-config.json /app/entrypoint.php

WORKDIR /app

# Expose default HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "Starting NGINX Unit..."\n\
/usr/local/unit/sbin/unitd \\\n\
  --no-daemon \\\n\
  --log /var/log/unit/unit.log \\\n\
  --state /var/lib/unit \\\n\
  --control unix:/var/run/unit/control.sock \\\n\
  --pid /var/run/unit/unit.pid \\\n\
  --modules /usr/local/unit/modules &\n\
\n\
UNITD_PID=$!\n\
\n\
echo "Waiting for control socket..."\n\
for i in {1..10}; do\n\
  if [ -S /var/run/unit/control.sock ]; then\n\
    echo "Control socket ready"\n\
    break\n\
  fi\n\
  sleep 1\n\
done\n\
\n\
if [ ! -S /var/run/unit/control.sock ]; then\n\
  echo "Control socket not available after 10 seconds"\n\
  exit 1\n\
fi\n\
\n\
echo "Loading configuration..."\n\
RESPONSE=$(curl -X PUT --data-binary @/app/unit-config.json \\\n\
  --unix-socket /var/run/unit/control.sock \\\n\
  http://localhost/config 2>&1)\n\
echo "$RESPONSE"\n\
\n\
if echo "$RESPONSE" | grep -q "error"; then\n\
  echo "ERROR: Configuration failed to load!"\n\
  echo "Response: $RESPONSE"\n\
  exit 1\n\
fi\n\
\n\
echo "Configuration loaded successfully"\n\
echo "NGINX Unit is ready and listening on http://0.0.0.0:8080"\n\
\n\
wait $UNITD_PID\n\
' > /app/start.sh \
    && chmod +x /app/start.sh \
    && chown unit:unit /app/start.sh

# Run as unit user
USER unit

# Start using startup script
CMD ["/app/start.sh"]
