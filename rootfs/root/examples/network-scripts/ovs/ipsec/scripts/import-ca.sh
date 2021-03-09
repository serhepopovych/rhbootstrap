#!/bin/sh

exec certutil -A -a -i 'example.net-root-ca-crt.pem' -d 'sql:/etc/ipsec.d' -n 'example.net-root-ca' -t 'CT,,'
