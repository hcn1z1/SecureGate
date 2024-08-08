from .encryption import generate_encryption_key
from .aes import encrypt,decrypt

__version__ = "1.0.0"
__name__ = "hcn1z1"

"""
This sub-package is made to encrypt and secure the data stored on the **AIDC** technology.
A default password goes through multiple security layers to generate an encryption key based on **n** keys randomly generated per user and stored.
"""