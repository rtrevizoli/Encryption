import rsa
import argparse
from pathlib import Path

print ('\\-------------------------------//')
print ('    **Decifrador de mensagens**   ')
print ('\\-------------------------------//')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key-path", type=str, required=True, help="Absolute or relative path for recipient's publict key.")
    parser.add_argument("--encrypted-msg-path", type=str, required=True, help="Absolute or relative path for encrypted message to be decrypted.")
    args = parser.parse_args()

    data = vars(args)

    if not check_path(data['private_key_path']):
        return
    
    if not check_path(data['encrypted_msg_path']):
        return
    
    private_key = load_recipent_private_key(data['private_key_path'])

    encrypted_msg = load_encrypted_message_from_file(data['encrypted_msg_path'])

    if not check_message(encrypted_msg):
        return

    decrypted_msg = rsa.decrypt(encrypted_msg, private_key).decode('utf-8')

    print("RTX | INFO | Decryptor::main(): Mensagem decifrada com sucesso")
    print(f"RTX | INFO | Decryptor::main(): Mensagem: {decrypted_msg}")

    return

def check_path(path: str) -> bool:
    print(f"RTX | DEBUG | Decryptor::check_path(): Checking filesystem path: '{path}'")

    p = Path(path)

    if not p.exists() or p.is_dir():
        print(f"RTX | DEBUG | Decryptor::check_path(): Provided path is invalid: {path}")
        return False

    return True

def check_message(msg: str) -> bool:
    print(f"RTX | DEBUG | Decryptor::check_message(): Checking message validity")

    if not msg:
        print("RTX | DEBUG | Decryptor::check_message(): Message is empty.")
        return False

    return True

def load_file_content(path: str) -> bytes:
    print(f"RTX | DEBUG | Decryptor::load_file_content(): Loading file content from '{path}'")

    content = b''

    try:
        with open(path,'rb') as f:
            content = f.read()
    except FileNotFoundError:
        print("RTX | DEBUG | Decryptor::load_file_content(): File not found.")
    except PermissionError:
        print("RTX | DEBUG | Decryptor::load_file_content(): No permission to read the file.")
    except OSError as e:
        print(f"RTX | DEBUG | Decryptor::load_file_content(): OS error while reading: {e}")
    except Exception as e:
        print(f"RTX | DEBUG | Decryptor::load_file_content(): Unexpected error: {e}")

    return content

def load_recipent_private_key(path: str) -> rsa.PublicKey:
    return rsa.PrivateKey.load_pkcs1(load_file_content(path), format='PEM')

def load_encrypted_message_from_file(path: str) -> bytes:
    return load_file_content(path)

if __name__ == "__main__":
    main()
