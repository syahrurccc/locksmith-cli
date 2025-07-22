# Locksmith CLI
### Description: 
🔐 Locksmith CLI – Simple Command-Line File Encryption & Decryption
Locksmith CLI is a lightweight, Python-based command-line tool for encrypting and decrypting files with secure password-based encryption. Designed with simplicity and clarity in mind, Locksmith provides a guided, user-friendly experience while maintaining robust protection using AES-128-CBC standards.

## Content
- [Key Features](#key-features)
- [Design Choices](#design-choices)
- [Drawbacks](#drawbacks--limitations)
- [How to Use](#how-to-use)

## Key Features
- AES-128-CBC Encryption — Secure file encryption using the cryptography library.
- Intelligent Prompts — Clear, interactive prompts for entering and confirming passwords.
- Password Verification — Ensures passwords match during encryption and checks against stored hashes during decryption.
- Overwrite Warnings — Notifies you when a file will be overwritten before proceeding.
- Optional Cleanup — Automatically removes original files after a successful operation.
- Error Logging — Failures are logged with timestamps for easier troubleshooting.
- Unit Tested — Core functionality is tested with pytest, including edge cases using unittest.mock.

## Design Choices
### Encryption with Fernet (AES-128 + HMAC-SHA256)
Rather than manually implementing cryptographic primitives, this app uses Fernet from Python’s cryptography library. Fernet provides:

- AES-128 in CBC mode for symmetric encryption
- HMAC-SHA256 for message authentication
- Timestamps to support expiration logic (unused here but supported)

Fernet uses a 32-byte key split into:

- 16 bytes for AES-128 encryption
- 16 bytes for HMAC

AES-128 is still considered secure and efficient for most use cases, especially when used alongside proper key derivation (like scrypt or PBKDF2) and safe password practices. Using Fernet ensures authenticated encryption and guards against both tampering and passive data leakage.

### Password-Driven Key Derivation
The user inputs a password, which is used to derive a secure Fernet key. This enables:

- Portability: No key files are saved or required
- Usability: Users only need to remember a password
- Security: The password is hashed using a slow algorithm (e.g., bcrypt), adding protection against brute-force attacks

### Command-Line Interface
The app is built as a command-line interface (CLI) for:

- Simplicity: Lightweight and scriptable, perfect for automation
- Portability: Easily installable in most Python environments

### Minimal External Dependencies
Only secure, well-maintained libraries are used:

- cryptography for encryption
- bcrypt for password hashing

### Safe File Handling
To prevent data loss or accidental overwrites:

- Overwrite confirmation is required if the output file already exists
- Decryption verifies password correctness before writing any file
- Secure deletion (optional) can be considered for future updates

## Drawbacks & Limitations
### Fernet Limitations
While Fernet is easy to use and secure, it comes with some trade-offs:

- Only AES-128 is supported: You can’t switch to AES-256 or other ciphers.
- No ChaCha20 support: Fernet does not support stream ciphers like ChaCha20, which are:
    - Faster on low-power or mobile devices (due to being CPU-friendly)

    - Considered more secure in environments without AES hardware acceleration

- No support for detached encryption/MAC: You can't separate the authentication tag or metadata.

- Lack of flexibility: You can’t customize nonce/IV generation, cipher mode (e.g., GCM), or KDF parameters.


Design trade-off: Fernet is chosen for safety, simplicity, and built-in authenticated encryption, even though it lacks the flexibility of lower-level cryptographic APIs.

### Password-Based Key Derivation
Single password = single point of failure: If the password is forgotten, the data is unrecoverable.

### Size limits
Since fernet encrypts/decrypts everything in memory. This makes it unsuitable for large files (>500MB), as it may lead to high RAM usage or crashes on constrained systems.

## How to Use
### Using Locksmith CLI 
A plain [_python script_](locksmith.py) is available to use in your system

### Locksmith CLI usage
```sh
# Encrypt a single file
python locksmith.py --encrypt file.docx 

# Encrypt multiple files
python locksmith.py --encrypt file.docx file.pdf audio.mp4

# Decrypt a folder
python locksmith.py --decrypt folder/ --key key.json

# See all available options
python locksmith.py -h
```

```
positional arguments:
  paths             the name of file(s)/folder(s) you want to encrypt/decrypt

optional arguments:
-h, --help          show this help message and exit
-e, --encrypt       encrypt file(s)/folder(s)
-d, --decrypt       decrypt file(s)/folder(s)
-k, --key           JSON file path containing key to decrypt files
```