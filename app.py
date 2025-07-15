from cryptography.fernet import Fernet
import argparse
import json
import os
import sys


def main():
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
                        help="JSON file path containing key to decrypt")
    parser.add_argument("paths", nargs=1, 
                        help="The name of file(s)/folder(s) you want to encrypt/decrypt")
    args = parser.parse_args()

    if args.encrypt:
        n, fail = encrypt(args.paths)
        if fail == 0:
            print(f"Encrypted: {n} file(s), failed: {fail} file(s), see logs.txt for details")
        else:
            print(f"Successfully encrypted {n} file(s)")

    elif args.decrypt:
        if not args.key:
            sys.exit("No keys provided")

        invalid_files = []
        invalid_logs = []
        
        for filename in args.paths:
            if not filename.endswith(".enc"):
                invalid_logs.append(f"{filename} cannot be decrypted")
                invalid_files.append(filename)

            elif not os.path.exists(filename):
                invalid_logs.append(f"{filename} does not exists")
                invalid_files.append(filename)

        valid_files = [file for file in args.paths if file not in invalid_files]

        n, fail, fail_logs = decrypt(valid_files, args.key)
        
        if fail > 0 or len(invalid_files) > 0:
            write_logs(fail_logs + invalid_logs)
            print(f"Decrypted: {n} file(s), failed: {fail} file(s), invalid: {len(invalid_files)} file(s), see logs.txt for details")
        else:
            print(f"Successfully decrypted {n} file(s)")


def encrypt(paths: list):
    key_map = {}
    encrypt_count = 0
    fail_count = 0
    fail_logs = []

    for path in paths:
        key = Fernet.generate_key()
        f = Fernet(key)

        try:
            with open(path, "rb") as original_file:
                data = original_file.read()

            encrypted_data = f.encrypt(data)
        except OSError:
            fail_logs.append(f"{path} cannot be opened")
            fail_count += 1
            continue

        encrypted_path = path + ".enc"
        if os.path.exists(encrypted_path):
            warning = input(f"WARNING: {encrypted_path} file already exists, do you want to overwrite it? [y/N] ")
            if warning.lower().strip() not in ["y", "yes"]:
                fail_logs.append(f"{encrypted_path} already exists")
                fail_count += 1
                continue
        
        with open(encrypted_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)
        os.remove(path)

        key_map[encrypted_path] = key.decode()
        encrypt_count += 1
    
    save_key(key_map)
    write_logs(fail_logs)

    return encrypt_count, fail_count

    
def decrypt(paths: list, key_path: str):
    if not os.path.exists(key_path):
        sys.exit("Key path does not exist")

    with open(key_path, "r") as file:
        key_map: dict = json.load(file)

    decrypt_count = 0
    fail_count = 0
    fail_logs = []

    for path in paths:
        output_path = path.rstrip(".enc")
        
        if path not in key_map:
            fail_logs.append(f"No key found for {path}")
            fail_count += 1
            continue

        elif os.path.exists(output_path):
            warning = input(f"WARNING: {output_path} already exists, do you want to overwrite? [y/N] ")
            if warning.lower().strip() not in ["y", "yes"]:
                fail_logs.append(f"{output_path} already exists")
                fail_count += 1
                continue

        key: str = key_map[path]
        f = Fernet(key.encode())

        try:
            with open(path, "rb") as encrypted_file:
                encrypted_data = encrypted_file.read()
            
            decrypted_data = f.decrypt(encrypted_data)

            with open(output_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)
            os.remove(path)
            decrypt_count += 1

        except OSError:
            fail_logs.append(f"{path} cannot be opened")
            fail_count += 1
            continue
    
    return decrypt_count, fail_count, fail_logs



def save_key(key_map, key_path="keys.json"):
    if os.path.exists(key_path):
        with open(key_path, "r") as file:
            existing_keys = json.load(file)
        
        for filename in key_map:
            if filename in existing_keys:
                warning = input(f"WARNING: Key for {filename} already exists, are you sure you want to proceed? [y/N] ")
                if warning.lower().strip() not in ["y", "yes"]:
                    continue
                existing_keys[filename] = key_map[filename]
        
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