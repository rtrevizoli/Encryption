import rsa
import argparse
from pathlib import Path

print ('\\-------------------------------//')
print ('     **Cifrador de mensagens**     ')
print ('\\-------------------------------//')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key-path", type=str, required=True, help="Absolute or relative path for recipient's publict key.")
    parser.add_argument("--msg", type=str, required=True, help="Message to be encrypted.")
    parser.add_argument("--output-path", type=int, help="Absolute or relative path for saving the encrypted message.")
    args = parser.parse_args()

    data = handle_args(vars(args))

    if not check_public_key_path(data['public_key_path']):
        return
    
    if not check_message(data['msg']):
        return
    
    public_key = load_recipent_public_key(data['public_key_path'])

    encrypted_msg = rsa.encrypt(data['msg'], public_key)

    if not write_encrypted_message_to_file(encrypted_msg, data['output_path']):
        return

    print("RTX | INFO | Encryptor::main(): Mensagem cifrada com sucesso")

    return

def handle_args(data: dict[str, any]) -> dict[str, any]:
    print(f"RTX | DEBUG | Encryptor::handle_args(): Data before handling: {data}")

    # check_msg()
    if data['msg'] is None:
        data['msg'] = ''
    
    data['msg'] = data['msg'].encode('utf-8')

    # check_output_path()
    if data['output_path'] is None:
        data['output_path'] = './'

    print(f"RTX | DEBUG | Encryptor::handle_args(): Data after handling: {data}")
    return data

def check_public_key_path(path: str) -> bool:
    print(f"RTX | DEBUG | Encryptor::check_public_key_path(): Checking public key path '{path}'")

    p = Path(path)

    if not p.exists() or p.is_dir():
        print(f"RTX | DEBUG | Encryptor::check_public_key_path(): Provided public key path is invalid: {path}")
        return False

    return True

def check_message(msg: str) -> bool:
    print(f"RTX | DEBUG | Encryptor::check_message(): Checking message validity")

    if not msg:
        print("RTX | DEBUG | Encryptor::check_message(): Message is empty.")
        return False

    return True

def load_recipent_public_key(path: str) -> rsa.PublicKey:
    print(f"RTX | DEBUG | Encryptor::load_recipent_public_key(): Loading recipient's public key from '{path}'")

    txt = b''
    pub = None

    try:
        with open(path,'rb') as f:
            txt = f.read()

        pub = rsa.PublicKey.load_pkcs1(txt, format='PEM')
    except FileNotFoundError:
        print("RTX | DEBUG | Encryptor::load_recipent_public_key(): Public key file not found.")
    except PermissionError:
        print("RTX | DEBUG | Encryptor::load_recipent_public_key(): No permission to read the public key file.")
    except OSError as e:
        print(f"RTX | DEBUG | Encryptor::load_recipent_public_key(): OS error while reading: {e}")
    except Exception as e:
        print(f"RTX | DEBUG | Encryptor::load_recipent_public_key(): Unexpected error: {e}")

    return pub

def get_key_file_path(path: str, key_name: str, is_public: bool) -> str:
    ext = "pub" if is_public else "pri"
    return f"{path}/{key_name}-{ext}.txt"

def write_encrypted_message_to_file(encrypted_msg: bytes, path: str) -> bool:
    print(f"RTX | DEBUG | Encryptor::write_encrypted_message_to_file(): Writing encrypted message to '{path}'")

    encrypted_msg_file_path = f"{path}/encrypted_message.txt"

    try:
        with open(encrypted_msg_file_path,'wb') as f:
            f.write(encrypted_msg)
    except FileNotFoundError:
        print("RTX | DEBUG | Encryptor::write_encrypted_message_to_file(): Folder does not exist.")
        return False
    except PermissionError:
        print("RTX | DEBUG | Encryptor::write_encrypted_message_to_file(): No permission to write here.")
        return False
    except OSError as e:
        print(f"RTX | DEBUG | Encryptor::write_encrypted_message_to_file(): OS error while writing: {e}")
        return False
    except Exception as e:
        print(f"RTX | DEBUG | Encryptor::write_encrypted_message_to_file(): Unexpected error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    main()
