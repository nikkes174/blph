#!/usr/bin/env sh
set -eu

if [ -z "${DOMAIN:-}" ]; then
  echo "DOMAIN is not set. Export DOMAIN before running."
  exit 1
fi

if [ -z "${LETSENCRYPT_EMAIL:-}" ]; then
  echo "LETSENCRYPT_EMAIL is not set. Export LETSENCRYPT_EMAIL before running."
  exit 1
fi

echo "Starting app and nginx..."
docker compose up -d app nginx

echo "Requesting Let's Encrypt certificate for ${DOMAIN}..."
docker compose run --rm --profile certbot certbot certonly \
  --webroot -w /var/www/certbot \
  -d "${DOMAIN}" \
  --email "${LETSENCRYPT_EMAIL}" \
  --agree-tos \
  --no-eff-email

echo "Reloading nginx..."
docker compose exec nginx nginx -s reload

echo "Done. HTTPS is enabled for ${DOMAIN}."
