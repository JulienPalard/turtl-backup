"""Backups a turtl account.

Backups are downloaded encrypted so they can be archived safely.
"""

import math
import os
from base64 import b64encode
from getpass import getpass
from hashlib import pbkdf2_hmac, sha256
from urllib.parse import urljoin

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = 5


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


def encode_payload_description(cipher='AES', block_mode='GCM') -> bytes:
    """This prepares a header telling which encryption is used.
    """
    ciphers = ['AES']
    block_modes = ['CBC', 'GCM']
    cipher_id = ciphers.index(cipher)
    block_mode_id = block_modes.index(block_mode)
    return bytes([cipher_id, block_mode_id])


def serialize(to_serialize, version, desc, iv) -> bytes:
    """This serialized the prepared header, prepending the version and the
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
    key = pbkdf2_hmac('sha256',
                      password.encode(),
                      sha256(username.encode()).hexdigest().encode(),
                      100000, 32)

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
