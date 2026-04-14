#!/bin/sh -ex

# make code boc
$TOS/build/crypto/func -A -P mergesort.fc >mergesort.fif
echo "boc>B \"mergesort.boc\" B>file" >>mergesort.fif
$TOS/build/crypto/fift -I $TOS/crypto/fift/lib mergesort.fif

# run code boc
echo "\"mergesort.boc\" file>B B>boc <s 1000 | rot 3 runvmx" >mergesort-run.fif
$TOS/build/crypto/fift -I $TOS/crypto/fift/lib mergesort-run.fif
