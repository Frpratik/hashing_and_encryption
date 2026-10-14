# hashing_and_encryption

A small Python demonstration of SHA-256 hashing, symmetric encryption with Fernet, and asymmetric encryption with RSA.

## Run

Install the dependency and run the script:

```powershell
python -m pip install cryptography
python simple_notes.py
```

The script prints examples of hashing text, encrypting and decrypting with a generated Fernet key, and encrypting and decrypting with an RSA key pair. The keys are generated for each run and are not saved.

The SHA-256 password example is for learning only. Production password storage should use a dedicated password-hashing algorithm such as Argon2id, scrypt, or bcrypt.