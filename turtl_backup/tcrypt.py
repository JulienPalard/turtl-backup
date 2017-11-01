"""
Parial Python implementation of
https://github.com/turtl/js/blob/2a68d3558abae0d875eb93d219de93f7b1573556/library/tcrypt.js
for use with turtl_backup.
"""

import math
import os
from base64 import b64decode

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
    assert version == 5, version
    len_desc = headers_and_ciphertext[2]
    assert len_desc == 2
    cipher_id = headers_and_ciphertext[3]
    block_id = headers_and_ciphertext[4]
    iv = headers_and_ciphertext[5:5+16]
    ciphertext = headers_and_ciphertext[5+16:]
    return (version, CIPHERS[cipher_id], BLOCK_MODES[block_id], iv, ciphertext)


def decrypt(key, headers_and_ciphertext):
    """Implementation of tcrypt decrypt, only supporting version 5 AES GCM.
    The tag is concatenated at the end of the ciphertext by sjcl.
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
