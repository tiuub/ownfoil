from db import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import zstandard as zstd
import random
import json
import os
import re

from titles import get_app_id_from_filename

# https://github.com/blawar/tinfoil/blob/master/docs/files/public.key 1160174fa2d7589831f74d149bc403711f3991e4
TINFOIL_PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvPdrJigQ0rZAy+jla7hS
jwen8gkF0gjtl+lZGY59KatNd9Kj2gfY7dTMM+5M2tU4Wr3nk8KWr5qKm3hzo/2C
Gbc55im3tlRl6yuFxWQ+c/I2SM5L3xp6eiLUcumMsEo0B7ELmtnHTGCCNAIzTFzV
4XcWGVbkZj83rTFxpLsa1oArTdcz5CG6qgyVe7KbPsft76DAEkV8KaWgnQiG0Dps
INFy4vISmf6L1TgAryJ8l2K4y8QbymyLeMsABdlEI3yRHAm78PSezU57XtQpHW5I
aupup8Es6bcDZQKkRsbOeR9T74tkj+k44QrjZo8xpX9tlJAKEEmwDlyAg0O5CLX3
CQIDAQAB
-----END PUBLIC KEY-----'''

def gen_shop_files(db):
    shop_files = []
    files = get_shop_files()
    for file in files:
        shop_files.append({
            "url": f'/api/get_game/{file["id"]}#{file["filename"]}',
            'size': file["size"]
        })
    return shop_files

SAVEGAME_TITLEID_REGEX = re.compile(r'([0-9A-Fa-f]{16})')

def _get_title_id_from_filename(filename):
    app_id = get_app_id_from_filename(filename)
    if app_id:
        return app_id.upper()

    match = SAVEGAME_TITLEID_REGEX.search(filename)
    if match:
        return match.group(1).upper()

    return None

def gen_shop_savegames(db):
    savegames = []
    files = get_savegame_files()

    for file in files:
        title_id = _get_title_id_from_filename(file['filename'])
        savegames.append({
            "titleid": title_id,
            "name": os.path.splitext(file['filename'])[0],
            "url": f"/api/get_game/{file['id']}#{file['filename']}",
            "size": file["size"]
        })

    return savegames

def encrypt_shop(shop):
    input = json.dumps(shop).encode('utf-8')
    # random 128-bit AES key (16 bytes), used later for symmetric encryption (AES)
    aesKey = random.randint(0,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).to_bytes(0x10, 'big')
    # zstandard compression
    flag = 0xFD
    cctx = zstd.ZstdCompressor(level=22)
    buf = cctx.compress(input)
    sz = len(buf)

    # Encrypt the AES key with RSA, PKCS1_OAEP padding scheme
    pubKey = RSA.importKey(TINFOIL_PUBLIC_KEY)
    cipher = PKCS1_OAEP.new(pubKey, hashAlgo = SHA256, label=b'')
    # Now the AES key can only be decrypted with Tinfoil private key
    sessionKey = cipher.encrypt(aesKey)

    # Encrypting the Data with AES
    cipher = AES.new(aesKey, AES.MODE_ECB)
    buf = cipher.encrypt(buf + (b'\x00' * (0x10 - (sz % 0x10))))

    binary_data = b'TINFOIL' + flag.to_bytes(1, byteorder='little') + sessionKey + sz.to_bytes(8, 'little') + buf
    return binary_data
