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
from typing import Tuple, Optional


def main():
    args = parse_arguments()
    deleted_paths = []

    try:
        paths, key_path, fail_count = validate_args(args.paths, args.key)
    except Exception as e:
        print(e)
        sys.exit(1)

    if args.encrypt:
        password: str = get_encrypt_password()
        fernet, salt = get_fernet(password, is_encrypt=True)
        key_map: dict = key_mapping(password, salt)

        for i, path in enumerate(paths, start=1):
            print(f"Encrypting {path} ({i}/{len(paths)})")

            try:
                input_data: bytes = read_file(path)
                processed_data: bytes = encrypt(input_data, fernet)
                write_file(processed_data, path, is_encrypt=True)
                deleted_paths.append(path)
                file_info = create_file_info(path)
                key_map["encrypted_files"].append(file_info)
            except OSError as e:
                print(f"Failed to encrypt {path}")
                write_logs(f"{path} Error: {e}")
                fail_count += 1
        
        save_key(key_map)

    elif args.decrypt:
        try:
            pw_hash, kdf_salt, key_map = load_key(key_path)
        except Exception as e:
            sys.exit(
                f"{e}: Failed to extract password and/or salt, check your .json file"
            )

        show_file_list(key_map)
        password = get_decrypt_password(pw_hash)
        fernet, _ = get_fernet(password, kdf_salt, is_encrypt=False)

        for i, path in enumerate(paths, start=1):
            print(f"Decrypting {path} ({i}/{len(paths)})")

            try:
                input_data = read_file(path)
                processed_data = decrypt(input_data, fernet)
                write_file(processed_data, path, is_encrypt=False)
                deleted_paths.append(path)
            except (OSError, InvalidToken) as e:
                print(f"Failed to decrypt {path}")
                write_logs(f"{path} Error: {e}")
                fail_count += 1
            
    delete_paths(deleted_paths)
    print(report(len(deleted_paths), fail_count, key_path))


def parse_arguments():
    """Parsing arguments given"""

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
        "-k",
        "--key",
        type=Path,
        default=None,
        help="JSON file path containing key to decrypt",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="The name of file(s)/folder(s) you want to encrypt/decrypt",
    )
    return parser.parse_args()


def validate_args(paths: list, key_path: Optional[Path] = None) -> Tuple[set, Optional[Path], int]:
    """Run a validation check on arguments"""

    valid_paths = set()
    fail_count = 0
    mode = "encrypt" if not key_path else "decrypt"

    if key_path and not key_path.exists():
        raise FileNotFoundError(f"Key not found: {key_path}")

    for path in paths:
        path = Path(path)

        if path.is_absolute():
            raise PermissionError("Root directory path is not allowed")
        elif not path.exists():
            write_logs(f"{path} does not exists")
            fail_count += 1
        elif path.is_file():
            if path.suffix != ".enc" and not key_path:
                write_logs(f"{path} cannot be decrypted")
                fail_count += 1
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

    return valid_paths, key_path, fail_count


def encrypt(input_data: bytes, fernet: Fernet) -> bytes:
    """Encrypt data then return encrypted data as bytes"""

    return fernet.encrypt(input_data)


def decrypt(input_data: bytes, fernet: Fernet) -> bytes:
    """Decrypt data then return decrypted data as bytes"""

    return fernet.decrypt(input_data)


def read_file(path: str) -> bytes:
    """Read given file then store it as bytes"""

    return Path(path).read_bytes()


def write_file(data: bytes, path: Path, is_encrypt=False):
    """Write file to computer's storage"""

    output_path: Path = Path(f"{path}.enc") if is_encrypt else Path(path).with_suffix("")

    if output_path.exists() and not confirmation(output_path):
        raise OSError(f"{output_path} already exists")

    output_path.write_bytes(data)


def get_encrypt_password() -> str:
    """Get encryption password from user"""

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

    while True:
        resubmit: str = (getpass.getpass("Re-enter password: ")).strip()

        if not resubmit:
            print("Please re-enter your password")
        elif resubmit != password:
            print("Password does not match")
        else:
            return password


def get_decrypt_password(pw_hash: str) -> str:
    """Get decryption password from user"""

    while True:
        password: str = getpass.getpass("Password: ")
        if not bcrypt.checkpw(password.encode(), pw_hash.encode()):
            print("Incorrect password")
            continue
        return password


def key_mapping(password: str, salt: bytes) -> dict:
    """Generate key map"""

    pw_hash: bytes = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    kdf_salt: bytes = base64.b64encode(salt)

    key_map = {
        "pw_hash": pw_hash.decode(),
        "salt_b64": kdf_salt.decode(),
        "encrypted_files": [],
    }

    return key_map


def create_file_info(path: Path) -> dict:
    """Generate file info"""

    file_info = {
        "original_path": str(path),
        "encrypted_path": f"{path}.enc",
        "encrypted_date": datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
        "file_size": os.path.getsize(path),
    }

    return file_info


def load_key(key_path: Path) -> Tuple[str, bytes, dict]:
    """Load password hash and salt hash from json file"""

    key_map: dict = json.loads(key_path.read_text())

    password: str = key_map["pw_hash"]
    kdf_salt: bytes = base64.b64decode(key_map["salt_b64"])

    return password, kdf_salt, key_map


def save_key(key_map: dict):
    """Save hashed password and salt"""

    while True:
        key_path_str = (input("Enter a name for the key file (must end in .json) ")).strip()
        if not key_path_str:
            print("Must provide a file name")
            continue
        elif not key_path_str.endswith(".json"):
            print("Key file format must be .json")
            continue

        key_path: Path = Path(key_path_str)

        if key_path.exists():
            print(
                f"{key_path} already exists. Please choose another name or delete the existing file"
            )
            continue
        break

    with open(key_path, "w") as file:
        json.dump(key_map, file, indent=4)


def get_fernet(password: str, salt: Optional[bytes]=None, is_encrypt=False) -> Tuple[Fernet, Optional[bytes]]:
    """Generate fernet object"""

    if is_encrypt:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    return Fernet(key), salt


def confirmation(path: Path) -> bool:
    """Prompt user for confirmation if file already exists"""

    warning = input(f"WARNING: {path} already exists, do you want to overwrite? [y/N] ")
    if warning.lower().strip() not in ["y", "yes"]:
        return False
    return True

# THIS NEEDS TO BE FIXED
def write_logs(logs: str):
    """Write logs if there are any failure"""

    output_logs = []
    output_logs.append(logs)

    if output_logs:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        p = Path(f"logs_{timestamp}.txt")
        p.write_text("\n".join(output_logs) + "\n")


def report(successes: int, fails: int, key_path: Optional[Path]=None) -> str:
    status = "encrypted" if not key_path else "decrypted"

    if fails > 0:
        return f"{status.capitalize()}: {successes} file(s), failed: {fails} file(s), see logs.txt for details"
    else:
        return f"Successfully {status} {successes} file(s)"


def delete_paths(paths: list):
    """Delete successfully processed files"""

    for path in paths:
        try:
            Path(path).unlink()
        except OSError as e:
            write_logs(f"Unexpected OS error: {e}")
            continue


def show_file_list(key_map: dict):
    """Show file lists that are available to decrypt in the key file"""

    show = input("Do you wish to see list of files that can be decrypted? [y/N] ")
    if show.lower().strip() in ["y", "yes"]:
        print("Encrypted files:")
        for i, file_list in enumerate(key_map["encrypted_files"]):
            print(f"{i+1}. {file_list["original_path"]}")


if __name__ == "__main__":
    main()
