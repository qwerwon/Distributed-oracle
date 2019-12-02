#!/usr/bin/env bash
num = $1

for ((i = 1; i <= $1; i++)); do
    openssl genrsa -out private$i.pem -3 3072
    openssl rsa -in private$i.pem -out public$i.pem -pubout
done
