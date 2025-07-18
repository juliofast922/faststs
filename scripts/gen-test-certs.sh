#!/bin/bash
set -e

mkdir -p certs

# CA
openssl req -x509 -nodes -days 1 \
  -newkey rsa:2048 \
  -keyout certs/ca.key \
  -out certs/ca.crt \
  -subj "/CN=FastCA"

# Server cert
openssl req -newkey rsa:2048 -nodes \
  -keyout certs/server.key -out certs/server.csr \
  -subj "/CN=localhost"

openssl x509 -req -in certs/server.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/server.crt -days 1

# Client cert with CN=fastclient
openssl req -newkey rsa:2048 -nodes \
  -keyout certs/client.key -out certs/client.csr \
  -subj "/CN=fastclient"

openssl x509 -req -in certs/client.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/client.crt -days 1
