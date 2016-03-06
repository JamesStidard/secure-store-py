# Secure Store
Helper functions for cryptography in Python.

## `securestore.hasher`
Helper functions for hashing and comparing values for storing sensitive data like passwords and API tokens.
Based on article from [CrackStation](https://crackstation.net/hashing-security.htm "CrackStation - Hashing Security").

#### def `create_hash`
Takes a string value and hashes its content into a HashStr type. The data of the hash returns in the format string format:
```python
str('{delimiter}{algorithm}{delimiter}{iterations}{delimiter}{salt}{delimiter}{hash}{delimiter}')
```

_The hash is calculated using Python's `hashlib.pbkdf2_hmac` function._

##### Method Signature
```python
def create_hash(value: str,
                 salt: bytes=None,
           iterations: int=10000,
            algorithm: str='sha512',
           salt_bytes: int=64,
            delimiter: str=':') -> HashStr:
    pass
```

| Parameter  | Required | Type   | Description                                                                                                                     |
| ---------: | :------: | :----: | ------------------------------------------------------------------------------------------------------------------------------- |
| value      | yes      | string | The string value to be hashed.                                                                                                  |
| salt       | no       | bytes  | A sequence of bytes to be used as a salt.                                                                                       |
| iterations | no       | int    | The number of iterations of the hash.                                                                                           |
| algorithm  | no       | str    | The string value of the hash algorithm to use. Available function names can be found by calling `hashlib.algorithms_available`. |
| salt_bytes | no       | int    | The number of bytes to use for the salt (if custom `salt` is not provided).                                                     |
| delimiter  | no       | str    | The character to use as a delimiter. Must not be a base64 character.                                                            |

#### def `guess_hash`
Takes a hash value and a un-hashed guess and return `True` or `False` if the guess produces a matching hash. The comparison uses the parameters stored on the HashStr so the hashing stratagem can be changed without breaking backwards compatibility.

_This function will cast the hash value to a string and use that result as the target value. This means a `HashStr` can be handed in without needing to get it's `.data` property._

##### Method Signature
```python
def guess_hash(hash_: str, guess: str) -> bool:
    pass
```

| Parameter  | Required | Type   | Description                                                                 |
| ---------: | :------: | :----: | --------------------------------------------------------------------------- |
| hash       | yes      | string | The hash to test against.                                                   |
| guess      | yes      | string | The value to test. Will be hashed using parameters stored on provided hash. |

#### def `slow_equals`
Performs a slow equals of two values. Used to evaluate equality in a method not susceptible to timing attacks.

_This function is called by `guess_hash`._

##### Method Signature
```python
def slow_equals(a, b) -> bool:
    pass
```

| Parameter | Required | Type   |
| --------: | :------: | :----: |
| a         | yes      | string |
| b         | yes      | string |

#### Class `HashStr`
A subclass of `collections.UserString` that holds the hash value.

_This function is called by `guess_hash`._

##### Method Signature
```python
def slow_equals(a, b) -> bool:
    pass
```

| Parameter | Required | Type   |
| --------: | :------: | :----: |
| a         | yes      | string |
| b         | yes      | string |
