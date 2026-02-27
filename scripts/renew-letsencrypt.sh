#!/usr/bin/env sh
set -eu

echo "Renewing certificates..."
docker compose run --rm --profile certbot certbot renew --webroot -w /var/www/certbot

echo "Reloading nginx..."
docker compose exec nginx nginx -s reload

echo "Renew complete."
