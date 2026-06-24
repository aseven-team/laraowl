FROM composer:2 AS composer

FROM php:8.3-fpm-alpine AS app
COPY --from=composer /usr/bin/composer /usr/bin/composer

# Install required dependencies
RUN apk --no-cache add \
    su-exec \
    postgresql-dev \
    libpng-dev \
    zlib-dev \
    oniguruma-dev \
    libzip-dev \
    zip \
    unzip \
    autoconf \
    gcc \
    g++ \
    make \
    bash \
    postgresql-client \
    linux-headers \
    libtool \
    nodejs \
    npm

# Add extra PHP dependencies
RUN docker-php-ext-install pdo pgsql pdo_pgsql gd bcmath zip exif pcntl \
    && pecl install redis \
    && docker-php-ext-enable redis \
    && docker-php-ext-configure pcntl --enable-pcntl

WORKDIR /usr/share/caddy/html/
COPY . .

# Install dependencies with composer
RUN composer validate --strict \
  && composer install \
  --no-interaction \
  --no-progress \
  --no-scripts \
  --no-dev \
  && composer clear-cache

# Install NPM dependencies and build frontend assets
RUN npm install \
  && npm run build \
  && rm -rf node_modules \
  && npm cache clean --force

# Set permissions and prepare Laravel
RUN php artisan package:discover --ansi \
  && chown -R www-data:www-data /usr/share/caddy/html/storage \
  && chown -R www-data:www-data /usr/share/caddy/html/bootstrap/cache \
  && chmod -R 775 /usr/share/caddy/html/storage \
  && chmod -R 775 /usr/share/caddy/html/bootstrap/cache

COPY ./docker/php-fpm-entrypoint /usr/local/bin/php-entrypoint

RUN chmod a+x /usr/local/bin/*

FROM app

ENTRYPOINT ["/usr/local/bin/php-entrypoint"]

CMD ["php-fpm"]
