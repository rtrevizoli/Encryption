import rsa
from pathlib import Path

class Decryptor:
    def __init__(self, private_key_path: str):
        self.__private_key = None
        self.__private_key_path_valid = False

        self.__set_recipient_private_key(private_key_path)

    def __set_recipient_private_key(self, path: str) -> None:
        print(f"RTX | DEBUG | Decryptor::__set_recipient_private_key(): Reading private key from '{path}'")

        if not self.__check_path(path, True):
            return False
        
        self.__private_key_path_valid = True
        print(f"RTX | DEBUG | Decryptor::__set_recipient_private_key(): self.__private_key_path_valid: {self.__private_key_path_valid}")

        self.__private_key = self.__load_recipient_private_key(path)

        return True
    
    def __load_recipient_private_key(self, path: str) -> rsa.PrivateKey | None:
        print(f"RTX | DEBUG | Decryptor::__load_recipient_private_key(): Loading recipient's private key from '{path}'")

        return rsa.PrivateKey.load_pkcs1(self.load_file_content(path), format='PEM')

    def __check_path(self, path: str, dir_check: bool = False) -> bool:
        print(f"RTX | DEBUG | Decryptor::__check_path(): Checking path '{path}'")

        p = Path(path)

        if not p.exists() or (dir_check and p.is_dir()):
            print(f"RTX | DEBUG | Decryptor::__check_path(): Provided path is invalid: {path}")
            return False
        
        return True

    def __check_message(self, msg: bytes) -> bool:
        print(f"RTX | DEBUG | Decryptor::__check_message(): Checking message validity")

        if not msg:
            print("RTX | DEBUG | Decryptor::__check_message(): Message is empty.")
            return False

        return True

    def load_file_content(self, path: str) -> bytes:
        print(f"RTX | DEBUG | Decryptor::load_file_content(): Loading file content from '{path}'")

        content = b''

        try:
            with open(path, 'rb') as f:
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

    def decrypt_message(self, encrypted_msg: bytes) -> str | None:
        print(f"RTX | DEBUG | Decryptor::decrypt_message(): Decrypting message")

        if not self.__private_key_path_valid:
            print("RTX | DEBUG | Decryptor::decrypt_message(): Private key path is not valid, could not decrypt message.")
            return None

        if not self.__check_message(encrypted_msg):
            return None

        decrypted_msg = rsa.decrypt(encrypted_msg, self.__private_key).decode('utf-8')

        print("RTX | INFO | Decryptor::decrypt_message(): Mensagem decifrada com sucesso")

        return decrypted_msg
