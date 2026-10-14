"""
==============================================================================
 HASHING  and  2 TYPES OF ENCRYPTION   -   the simplest version
==============================================================================
 RUN:  pip install cryptography      then      python simple_notes.py

 THE 3 THINGS (one picture each)

   HASHING               = MEAT GRINDER   beef -> mince, you can't go back
   SYMMETRIC ENCRYPTION  = ONE KEY        the same key locks AND unlocks
   ASYMMETRIC ENCRYPTION = MAILBOX        public key locks, private key unlocks

 ONE QUESTION TO DECIDE
   Do I need the original data back?   YES -> encrypt      NO -> hash
==============================================================================
"""
import hashlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ==============================================================================
# 1. HASHING  (one-way)
# ==============================================================================
# Text goes in, a fixed-length "fingerprint" comes out. You can NEVER get the text back.

print("--- 1. HASHING ---")

def hash_it(text):
    return hashlib.sha256(text.encode()).hexdigest()

print(hash_it("hello"))        # always this same fingerprint for "hello"
print(hash_it("hello"))        # same input -> same output
print(hash_it("hellp"))        # change ONE letter -> totally different output
print(len(hash_it("hi")), len(hash_it("a very very long sentence")))   # 64 and 64: always same length

# USE CASE: storing passwords. We never store the password, only its hash.
stored_hash = hash_it("mypassword")          # saved in the database at sign-up

# At login: hash what the user typed and compare the two fingerprints.
print("login with right password:", hash_it("mypassword") == stored_hash)   # True
print("login with wrong password:", hash_it("wrongpass") == stored_hash)    # False
# Even if the database is stolen, the hacker only sees fingerprints, not passwords.
#
# (Real apps also add a random "salt" and use a slow hash like bcrypt/PBKDF2.
#  Django does all of that for you. For now, just understand the idea.)


# ==============================================================================
# 2. SYMMETRIC ENCRYPTION  (ONE key does both jobs)
# ==============================================================================
# Like a house key: the same key locks the door and unlocks it.
# Fast. Problem: both people need the same key, so how do you share it safely?
# Famous one: AES.

print("\n--- 2. SYMMETRIC (one key) ---")

key = Fernet.generate_key()              # the ONE secret key. Keep it safe!
box = Fernet(key)

locked = box.encrypt(b"my card number is 1234")      # lock it
print("locked   :", locked[:40], "...")              # unreadable gibberish
print("unlocked :", box.decrypt(locked))             # same key opens it -> original is back

# USE CASE: encrypting a database column, a file, or a backup.


# ==============================================================================
# 3. ASYMMETRIC ENCRYPTION  (TWO keys: public + private)
# ==============================================================================
# Like a mailbox: ANYONE can drop a letter in (public key),
#                 only YOU can open it (private key).
# Slower, but solves the sharing problem: you can hand out the public key freely.
# Famous one: RSA.

print("\n--- 3. ASYMMETRIC (two keys) ---")

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # keep secret
public_key = private_key.public_key()                                          # share with everyone

rules = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)   # (just required settings)

locked = public_key.encrypt(b"meet me at 6pm", rules)         # anyone can lock with the PUBLIC key
print("locked   :", locked[:20].hex(), "...")
print("unlocked :", private_key.decrypt(locked, rules))       # only the PRIVATE key opens it

# USE CASE: sending a secret to someone you have never met (this is how HTTPS starts).


# ==============================================================================
# SUMMARY
# ==============================================================================
#                  Hashing        Symmetric        Asymmetric
#  Keys            none           1 shared key     public + private pair
#  Reversible?     NO             YES (with key)   YES (with private key)
#  Speed           fast           fast             slow
#  Picture         meat grinder   one house key    mailbox
#  Use for         passwords,     big data,        sharing secrets,
#                  integrity      files, DBs       HTTPS handshake
#
#  HTTPS = both encryptions together:
#     asymmetric to safely agree on a secret, then symmetric to talk fast.
#     ("Asymmetric to MEET, symmetric to TALK.")
# ==============================================================================
