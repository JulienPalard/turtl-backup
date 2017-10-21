"""Backups a turtl account.

Backups are downloaded encrypted so they can be archived safely.
"""

import json
import math
import os
from base64 import b64encode, b64decode
from getpass import getpass
from hashlib import pbkdf2_hmac, sha256
from urllib.parse import urljoin

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = 5
CIPHERS = ['AES']
BLOCK_MODES = ['CBC', 'GCM']


def encrypt(key, plaintext, utf8_random, iv=None, associated_data=None):
    """Encrypt as done in Turtl: AES GCM with a prefix telling if it's
    UTF8 or binary,
    """
    # Generate a random 96-bit IV if needed
    if iv is None:
        iv = os.urandom(12)
    if isinstance(plaintext, str):
        utf8byte = chr(math.floor(utf8_random * (256 - 128)) + 128)
        plaintext = utf8byte.encode() + plaintext.encode()
    else:
        utf8byte = chr(math.floor(utf8_random * (256 - 128)))
        plaintext = utf8byte.encode() + plaintext
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)


def deserialize(headers_and_ciphertext: bytes):
    """This invert the work of serialize.

    returns: version, cipher, block_mode, iv, ciphertext
    """
    version_high_bit = headers_and_ciphertext[0] << 8
    version_low_bits = headers_and_ciphertext[1]
    version = version_high_bit | version_low_bits
    assert version == 5
    len_desc = headers_and_ciphertext[2]
    assert len_desc == 2
    cipher_id = headers_and_ciphertext[3]
    block_id = headers_and_ciphertext[4]
    iv = headers_and_ciphertext[5:5+16]
    ciphertext = headers_and_ciphertext[5+16:]
    return (version, CIPHERS[cipher_id], BLOCK_MODES[block_id], iv, ciphertext)


def decrypt(key, headers_and_ciphertext):
    """Implementation of tcrypt decrypt, only supporting version 5 AES GCM.
    """
    headers_and_cipherbytes = b64decode(headers_and_ciphertext)
    version, cipher, block_mode, iv, ciphertext = deserialize(
        headers_and_cipherbytes)
    assert version == 5
    assert cipher == 'AES'
    assert block_mode == 'GCM'
    tag = ciphertext[-16:]
    ciphertext = ciphertext[:-16]
    adata = headers_and_cipherbytes[:21]  # All but ciphertext
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(adata)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    deciphered = decryptor.update(ciphertext) + decryptor.finalize()
    return deciphered[1:]  # Without tcrypt's utf8 byte


def encode_payload_description(cipher='AES', block_mode='GCM') -> bytes:
    """This prepares a header telling which encryption is used.
    """
    cipher_id = CIPHERS.index(cipher)
    block_mode_id = BLOCK_MODES.index(block_mode)
    return bytes([cipher_id, block_mode_id])


def serialize(to_serialize, version, desc, iv) -> bytes:
    """This serializes the prepared header, prepending the version and the
    length of the following header.
    """
    return (bytes([version >> 8, version & 255, len(desc)]) +
            desc + iv + to_serialize)


def parse_args():
    """Parses command line arguments.
    """
    import argparse
    parser = argparse.ArgumentParser(
        description='Backup a turtl account.')
    parser.add_argument(
        'server', help='Your turtle server')
    parser.add_argument(
        'dest', help='Destination file, where your notes will be stored encrypted')
    return parser.parse_args()


def get_key(username, password):
    """Build the symmetric encryption key with the given user and passord.
    """
    return pbkdf2_hmac('sha256',
                       password.encode(),
                       sha256(username.encode()).hexdigest().encode(),
                       100000, 32)


def get_auth(username, password, version=VERSION):
    """Get a basic authorization token for the given username and
    password, which is:

    login:password encrypted using AES-GCM with a key derived from the
    actual password salted with the sha256 of the login.
    """
    seed = sha256((password + username).encode('utf8')).hexdigest()
    user_record = (sha256(password.encode('utf8')).hexdigest() + ':' +
                   sha256(username.encode('utf8')).hexdigest())
    auth_iv = seed[:16].encode()
    utf8_random = int(user_record[18:20], 16) / 256
    key = get_key(username, password)
    desc = encode_payload_description()
    formatted = serialize(b'', version, desc, auth_iv)
    _, cipher, tag = encrypt(key, user_record.encode(), utf8_random,
                             auth_iv, formatted)
    auth = b64encode(formatted + cipher + tag)
    return 'Basic ' + b64encode(b'user:' + auth).decode()


def main():
    """Module entry point.
    """
    args = parse_args()
    username = input('username: ')
    password = getpass('password: ')
    basic_auth = get_auth(username, password)
    response = requests.get(urljoin(args.server, '/sync/full'),
                            headers={'authorization': basic_auth})
    with open(args.dest, 'w') as dest:
        dest.write(response.text)


if __name__ == '__main__':
    main()
