#!/bin/sh -e
#sudo modprobe pkcs8_key_parser
KEY="$(openssl genrsa | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w 0)"
KEYID=$(echo ${KEY} | base64 -d | keyctl padd asymmetric signkey @u)
echo "Keyring ID: $KEYID"
echo "Public key:"
echo $KEY | base64 -d | openssl rsa -inform der -pubout
