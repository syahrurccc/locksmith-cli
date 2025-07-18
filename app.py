import argparse
import base64
import bcrypt
import getpass
import json
import os
import sys
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
from pathlib import Path


def main():
    args = parse_arguments()

    if args.encrypt:
        print(validate_args(args.paths, is_encrypt=True))

    elif args.decrypt:
        print(validate_args(args.paths, args.key, is_encrypt=False))


def parse_arguments():

    parser = argparse.ArgumentParser(
        description="Encrypt or Decrypt file(s) or folder(s)"
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-e", "--encrypt", help="Encrypt file(s)/folder(s)", action="store_true"
    )
    group.add_argument(
        "-d", "--decrypt", help="Decrypt file(s)/folder(s)", action="store_true"
    )
    parser.add_argument(
        "-k", "--key", type=Path, help="JSON file path containing key to decrypt"
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="The name of file(s)/folder(s) you want to encrypt/decrypt",
    )
    return parser.parse_args()


def validate_args(paths: str, key_path: Path = None, is_encrypt=True):
    """Run a validation check on arguments"""

    valid_paths = set()
    invalid_count = 0
    
    mode = "encrypt" if is_encrypt else "decrypt"

    if not is_encrypt:
        if not key_path or not key_path.exists():
            sys.exit("No valid key provided")

    for path in paths:
        path = Path(path)
        if path.is_absolute():
            sys.exit("Root directory path is not allowed")
        elif not path.exists():
            write_logs(f"{path} does not exists")
            invalid_count += 1
        elif path.is_file():
            if path.suffix != ".enc" and not is_encrypt:
                write_logs(f"{path} cannot be decrypted")
                invalid_count += 1
            else:
                valid_paths.add(path)
        elif path.is_dir():
            warning = input(
                f"WARNING: Do you wish to {mode} all the files inside the subdirectiories of this folder? [y/N] "
            )
            if warning.lower().strip() in ["y", "yes"]:
                valid_paths.update([file for file in path.rglob("*") if file.is_file()])
            else:
                valid_paths.update([file for file in path.iterdir() if file.is_file()])

    n, fail = (
        encrypt(list(valid_paths))
        if is_encrypt
        else decrypt(list(valid_paths), key_path)
    )
    status = "encrypted" if is_encrypt else "decrypted"

    if fail > 0 or invalid_count > 0:
        return f"{status.capitalize()}: {n} file(s), failed: {fail} file(s), invalid: {invalid_count} file(s), see logs.txt for details"
    else:
        return f"Successfully {status} {n} file(s)"


def encrypt(paths: list) -> int:
    """encrypt files then return reports"""

    encrypt_count = 0
    fail_count = 0

    while True:
        password: str = (
            getpass.getpass("Password (minimum of 8 characters): ")
        ).strip()

        if not password:
            print("Please enter a password")
        elif not 8 <= len(password) <= 32:
            print("Please enter 8 to 32 characters")
        elif not password.isascii():
            print("Password can only contains alphabet, digits, or punctuation")
        else:
            break

    salt: bytes = os.urandom(16)
    fernet: Fernet = get_fernet(password, salt)

    pw_hash: bytes = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    key_map = {
        "pw_hash": pw_hash.decode(),
        "salt_b64": base64.b64encode(salt).decode(),
        "encrypted_files": []
    }

    for file_path in paths:
        file_path = Path(file_path)

        encrypted_path = Path(f"{file_path}.enc")
        if encrypted_path.exists() and not prompt_user(encrypted_path):
            write_logs(f"{encrypted_path} already exists")
            fail_count += 1
            continue
        try:
            original_data: bytes = file_path.read_bytes()
            encrypted_data: bytes = fernet.encrypt(original_data)
        except OSError:
            write_logs(f"{file_path} cannot be opened")
            fail_count += 1
            continue

        file_list = {
            "original_path": str(file_path),
            "encrypted_path": str(encrypted_path),
            "encrypted_date": datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
            "file_size": os.path.getsize(str(file_path)),
        }

        key_map["encrypted_files"].append(file_list)

        encrypted_path.write_bytes(encrypted_data)
        file_path.unlink()
        encrypt_count += 1

    save_key(key_map)

    return encrypt_count, fail_count


def decrypt(paths: list, key_path: Path) -> int:

    decrypt_count = 0
    fail_count = 0

    key_map: dict = json.loads(key_path.read_text())
    pw_hash: str = key_map["pw_hash"]
    salt_b64: str = key_map["salt_b64"]

    show = input("Do you wish to see list of files that can be decrypted? [y/N] ")
    if show.lower().strip() in ["y", "yes"]:
        print("Encrypted files:")
        for i, file_list in enumerate(key_map["encrypted_files"]):
            print(f"{i+1}. {file_list["original_path"]}")

    while True:
        password: str = getpass.getpass("Password: ")
        if not bcrypt.checkpw(password.encode(), pw_hash.encode()):
            print("Incorrect password")
            continue
        break

    kdf_salt: bytes = base64.b64decode(salt_b64)
    fernet: Fernet = get_fernet(password, kdf_salt)

    for file_path in paths:

        file_path = Path(file_path)
        decrypted_path: Path = file_path.with_suffix("")

        if decrypted_path.exists() and not prompt_user(decrypted_path):
            write_logs(f"{decrypted_path} skipped, file already exists")
            fail_count += 1
            continue
        try:
            encrypted_data: bytes = file_path.read_bytes()
            decrypted_data: bytes = fernet.decrypt(encrypted_data)
            decrypted_path.write_bytes(decrypted_data)
            file_path.unlink()
            decrypt_count += 1
        except OSError:
            write_logs(f"{file_path} cannot be opened")
            fail_count += 1
            continue
        except InvalidToken:
            write_logs(f"{file_path} token does not match the given key")
            fail_count += 1
            continue

    return decrypt_count, fail_count


def save_key(key_map: dict):
    """Save hashed password and salt"""

    while True:
        key_path = (input("Enter a name for the key file (must end in .json) ")).strip()
        if not key_path:
            print("Must provide a file name")
            continue
        elif not key_path.endswith(".json"):
            print("Key file format must be .json")
            continue

        key_path = Path(key_path)

        if key_path.exists():
            print(
                f"{str(key_path)} already exists. Please choose another name or delete the existing file"
            )
            continue
        break

    with open(key_path, "w") as file:
        json.dump(key_map, file, indent=4)


def get_fernet(password: str, salt) -> Fernet:
    """Generate fernet object"""

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)


def prompt_user(path: Path) -> bool:
    """Prompt user for confirmation if file already exists"""

    warning = input(f"WARNING: {path} already exists, do you want to overwrite? [y/N] ")
    if warning.lower().strip() not in ["y", "yes"]:
        return False
    return True


def write_logs(logs: str):
    """Write logs if there any failure"""

    output_logs = []
    output_logs.append(logs)
    
    if output_logs:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        p = Path(f"logs_{timestamp}.txt")
        p.write_text("\n".join(output_logs) + "\n")

if __name__ == "__main__":
    main()
