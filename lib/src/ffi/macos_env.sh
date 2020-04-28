#!/bin/bash

export LDFLAGS="${LDFLAGS} -L/usr/local/opt/openssl/lib -L/usr/local/lib"
export CFLAGS="${CFLAGS} -I/usr/local/opt/openssl/include/ -I/usr/local/include"
export CPPFLAGS="${CPPFLAGS} -I/usr/local/opt/openssl/include/ -I/usr/local/include"

