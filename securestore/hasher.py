import hashlib
import os
import base64
from collections import UserString

__author__ = 'James Stidard'


class HashStr(UserString):

    def __eq__(self, other):
        if isinstance(other, HashStr):
            return self.data == other.data
        else:
            return guess_hash(self.data, other)


def create_hash(value: str,
                 salt: bytes=None,
           iterations: int=10000,
            algorithm: str='sha512',
           salt_bytes: int=64,
            delimiter: str=':'):
    salt  = os.urandom(salt_bytes) if not salt else salt
    hash_ = hashlib.pbkdf2_hmac(algorithm, value.encode(), salt, iterations)

    return HashStr('{0}{algorithm}{0}{iterations}{0}{salt}{0}{hash}{0}'.format(
        delimiter,
        algorithm=algorithm,
        iterations=iterations,
        salt=base64.encodebytes(salt).decode(),
        hash=base64.encodebytes(hash_).decode()
    ))


def guess_hash(hash_: str, guess: str):
    parts     = str(hash_)
    delimiter = parts[0]

    algorithm, iterations, salt, prev_hash = parts[1:-1].split(delimiter)

    guess = hashlib.pbkdf2_hmac(
        algorithm,
        guess.encode(),
        base64.b64decode(salt),
        int(iterations)
    )

    prev_hash = base64.b64decode(prev_hash)
    return slow_equals(prev_hash, guess)


def slow_equals(a, b) -> bool:
    diff, i = len(a) ^ len(b), 0
    while i < len(a) and i < len(b):
        diff |= a[i] ^ b[i]
        i    += 1
    return diff == 0
