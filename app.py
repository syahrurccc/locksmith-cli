import argparse
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
import json
import sys


def main():
    args = parse_arguments()

    if args.encrypt:
        print(validate_args(args.paths, is_encrypt=True))

    elif args.decrypt:
        print(validate_args(args.paths, args.key, is_encrypt=False))
        

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Encrypt or Decrypt file(s) or folder(s)")

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-e", "--encrypt", 
                    help="Encrypt file(s)/folder(s)", 
                    action="store_true")
    group.add_argument("-d", "--decrypt", 
                    help="Decrypt file(s)/folder(s)", 
                    action="store_true")
    parser.add_argument("-k", "--key",
                        type=Path,
                        help="JSON file path containing key to decrypt")
    parser.add_argument("paths", nargs="+", 
                        help="The name of file(s)/folder(s) you want to encrypt/decrypt")
    return parser.parse_args()


def validate_args(paths, key_path=None, is_encrypt=True):
    
    if not is_encrypt:
        if not key_path:
            sys.exit("No keys provided")
        elif not key_path.exists():
            sys.exit("Key path does not exist")

    valid_paths = set()
    invalid_paths = []
    invalid_logs = []
    mode = "encrypt" if is_encrypt else "decrypt"
    
    for path in paths:
        path = Path(path)
        if not path.exists():
            invalid_logs.append(f"{path} does not exists")
            invalid_paths.append(path)
        elif path.is_file():
            if path.suffix != ".enc" and not is_encrypt:
                invalid_logs.append(f"{path} cannot be decrypted")
                invalid_paths.append(path)
            else:
                valid_paths.add(path)
        elif path.is_dir():
            warning = input(f"WARNING: Do you wish to {mode} all the files inside the subdirectiories of this folder? [y/N] ")
            if warning.lower().strip() in ["y", "yes"]:
                valid_paths.update([file for file in path.rglob("*") if file.is_file()])
            else:
                valid_paths.update([file for file in path.iterdir() if file.is_file()])

    n, fail, fail_logs = encrypt(list(valid_paths)) if is_encrypt else decrypt(list(valid_paths), key_path)
    status = "encrypted" if is_encrypt else "decrypted"
    
    if fail > 0 or len(invalid_paths) > 0:
        write_logs(fail_logs + invalid_logs)
        return f"{status.capitalize()}: {n} file(s), failed: {fail} file(s), invalid: {len(invalid_paths)} file(s), see logs.txt for details"
    else:
        return f"Successfully {status} {n} file(s)"


def encrypt(paths: list):
    key_map = {}
    encrypt_count = 0
    fail_count = 0
    fail_logs = []

    for file_path in paths:
        file_path = Path(file_path)

        key = Fernet.generate_key()
        f = Fernet(key)

        encrypted_path = Path(f"{file_path}.enc")
        if encrypted_path.exists():
            warning = input(f"WARNING: {encrypted_path} file already exists, do you want to overwrite it? [y/N] ")
            if warning.lower().strip() not in ["y", "yes"]:
                fail_logs.append(f"{encrypted_path} already exists")
                fail_count += 1
                continue

        try:
            original_data = file_path.read_bytes()
            encrypted_data = f.encrypt(original_data)
        except OSError:
            fail_logs.append(f"{file_path} cannot be opened")
            fail_count += 1
            continue

        encrypted_path.write_bytes(encrypted_data)
        file_path.unlink()

        key_map[str(encrypted_path)] = key.decode()
        encrypt_count += 1
    
    save_key(key_map)

    return encrypt_count, fail_count, fail_logs


def decrypt(paths: list, key_path: Path):
    
    key_map: dict = json.loads(key_path.read_text())

    decrypt_count = 0
    fail_count = 0
    fail_logs = []

    for file_path in paths:
        
        file_path = Path(file_path)
        decrypted_path = file_path.with_suffix("")
        
        if str(file_path) not in key_map:
            fail_logs.append(f"No key found for {file_path}")
            fail_count += 1
            continue

        elif decrypted_path.exists():
            warning = input(f"WARNING: {decrypted_path} already exists, do you want to overwrite? [y/N] ")
            if warning.lower().strip() not in ["y", "yes"]:
                fail_logs.append(f"{decrypted_path.stem} skipped, file already exists")
                fail_count += 1
                continue

        key: str = key_map[str(file_path)]
        f = Fernet(key.encode())

        try:
            encrypted_data = file_path.read_bytes()
            decrypted_data = f.decrypt(encrypted_data)
            decrypted_path.write_bytes(decrypted_data)
            file_path.unlink()
            decrypt_count += 1

        except OSError:
            fail_logs.append(f"{file_path} cannot be opened")
            fail_count += 1
            continue
        except InvalidToken:
            fail_logs.append(f"{file_path} token does not match the given key")
            fail_count += 1
            continue
    
    return decrypt_count, fail_count, fail_logs


def save_key(key_map, key_path="keys.json"):
    key_path = Path(key_path)
    if key_path.exists():
        existing_keys = json.loads(key_path.read_text())
        
        for file_path in key_map:
            if file_path in existing_keys:
                warning = input(f"WARNING: Key for {file_path} already exists, FILES WITHOUT KEYS CANNOT BE DECRYPTED, are you sure you want to proceed? [y/N] ")
                if warning.lower().strip() not in ["y", "yes"]:
                    continue
                existing_keys[file_path] = key_map[file_path]
        
        with open(key_path, "w") as file:
            json.dump(existing_keys, file, indent=4)

    else:
        with open(key_path, "w") as file:
            json.dump(key_map, file, indent=4)


def write_logs(fail_logs):
    with open("logs.txt", "w") as logs:
        for log in fail_logs:
            logs.write(log + "\n")


if __name__=="__main__":
    main()