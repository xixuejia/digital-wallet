#!/bin/bash

ifconfig lo 127.0.0.1
ifconfig

sarproxy &
socat VSOCK-LISTEN:8080,reuseaddr,fork TCP4:localhost:8080 &
rngd &
/root/sign-service -k /root/key.pem -s -p 1024
