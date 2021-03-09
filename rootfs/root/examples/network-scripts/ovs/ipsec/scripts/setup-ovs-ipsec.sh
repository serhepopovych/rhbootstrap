#!/bin/sh

ovs-vsctl \
    set Open_vSwitch . \
    \
    other_config:ca_cert='example.net-inter-ca-crt.pem' \
    other_config:certificate='ovs.example.net-crt.pem' \
    other_config:private_key='ovs.example.net-key.pem' \
    \
    other_config:ipsec_skb_mark=0/1 \
    #
