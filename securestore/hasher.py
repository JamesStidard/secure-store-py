import os
import hashlib
import base64
from collections import UserString, namedtuple
from typing import Tuple

__author__ = 'James Stidard'


Parts = namedtuple('Parts', 'algorithm iterations salt hash')

class HashStr(UserString):

    @classmethod
    def from_parts(cls, algorithm: str, iterations: int, salt: bytes, hash_: bytes, delimiter: str):
        # TODO: assert delimiter isn't in char set
        # TODO: encode algorithm
        if len(delimiter) != 1:
            ValueError('Delimiter must be a single character.')

        return '{algorithm}{0}{iterations}{0}{salt}{0}{hash}{0}'.format(
            delimiter,
            algorithm=algorithm,
            iterations=iterations,
            salt=base64.encodebytes(salt).decode(),
            hash=base64.encodebytes(hash_).decode()
        )

    @staticmethod
    def parts_from_str(value: str, delimiter: str) -> Tuple[str, int, str, str]:
        algorithm, iterations, salt, hash_ = value[:-1].split(delimiter)

        return Parts(
            algorithm,
            int(iterations),
            base64.b64decode(salt),
            base64.b64decode(hash_),
        )

    @staticmethod
    def delimiter_from_str(value: str) -> str:
        return value[-1]

    def __init__(self, value):
        delimiter = self.delimiter_from_str(value)
        parts     = self.parts_from_str(value, delimiter)
        self.data = self.from_parts(*parts, delimiter)

    @property
    def parts(self) -> Tuple[str, int, str, str]:
        return self.parts_from_str(self.data, self.delimiter)

    @property
    def delimiter(self) -> str:
        return self.delimiter_from_str(self.data)

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
            delimiter: str=':') -> HashStr:
    salt  = os.urandom(salt_bytes) if not salt else salt
    hash_ = hashlib.pbkdf2_hmac(algorithm, value.encode(), salt, iterations)

    return HashStr.from_parts(algorithm, iterations, salt, hash_, delimiter)


def guess_hash(hash_: str, guess: str) -> bool:
    parts = HashStr(hash_).parts
    guess = hashlib.pbkdf2_hmac(
        parts.algorithm,
        guess.encode(),
        parts.salt,
        parts.iterations
    )

    return slow_equals(parts.hash, guess)


def slow_equals(a, b) -> bool:
    diff, i = len(a) ^ len(b), 0
    while i < len(a) and i < len(b):
        diff |= a[i] ^ b[i]
        i    += 1
    return diff == 0
