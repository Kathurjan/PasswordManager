# Prototype program

This program is a small python executable that uses PBKDF2 to secure an initial master password and a symmetric AES cipher to encrypt the stored passwords within a file.

## PBKDF2

PBKDF2 is a process of using multiple iterations of hashing to encrypt a password. It requires a fair bit of computational processing to accomplish and is therefore only used for the Master password in this case.

```python
def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,  # High iteration count for computational cost against brute-force attacks
            backend=default_backend()
        )
        return kdf.derive(password.encode())
```

## AES Cipher

An AES cipher is a method by which we permeate over a given plaintext password using the master-key as a type of salt. This shuffles the password in a 16 byte grid with different steps to produce a new string of unintelligible nonsense that we can however decrypt using the same algorithm and the master-key.

```python
    def encrypt(self, plain_text):
        iv = os.urandom(16)  # Generate a random initialization vector (IV)
        cipher = Cipher(algorithms.AES(self.master_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_text).decode()  # Encode IV + encrypted text as base64

    # Decrypt the given cipher text using AES in CFB mode
    def decrypt(self, cipher_text):
        try:
            decoded_data = base64.b64decode(cipher_text)
            iv = decoded_data[:16]  # Extract the IV from the decoded data
            encrypted_text = decoded_data[16:]
            cipher = Cipher(algorithms.AES(self.master_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
            return decrypted_text.decode()
        except (ValueError, UnicodeDecodeError) as e:
            print(f"Decryption error: {e}")
            return None
```

# Further plans
This functions as a local prototype but we should plan to make this a distributed solution.

Taking a page out of 1pass https://support.1password.com/1password-security/ we would keep a secret key stored locally that is combined with the account password to encrypt the entire collection of data.

In order to retrieve the data we would use the password along with the locally stored secret key to decrypt a small part and validate the correctness of the password.

in order to use multiple devices the user must transfer their secret key to the new device. The account password is therefore never stored.

For communication with the server we can use HTTPS whice secure our inter application communication.

## Diffe-helman

A mathematical code sharing method that enables a process in which two parties can obtain a shared secret while still utilizing an public communication channel. 

## RSA

RSA is a method by which we can verify the authenticity of a communicator. By having a recipient utilize a private and public key pair they can both verify incoming and outgoing messages.

This prevents man in the middle attacks that are a key weakness to pure diffe-hellman.
