#!/bin/bash

mkdir -p certs
cd certs

openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
