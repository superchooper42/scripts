#!/usr/bin/python3
from Crypto.Cipher import AES
import base64

key = "0d43e09e2fcc8214e9e2d4d31cbde907ffa226d988054299467d3a9a6994a831"
ccb64 = "2edEX8jblFU0IxXHnNAdPbDZgsx1imLa7he43lk7px0bKVLQknPaABEpR8mo2kwn"
iv = "\x00" * 16 

print(AES.new(bytes.fromhex(key), AES.MODE_CBC, iv).decrypt(base64.b64decode(ccb64)))