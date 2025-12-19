import rsa
from pathlib import Path

class Encryptor:
    def __init__(self, public_key_path: str):
        self.__public_key_path = None
        self.__public_key_path_valid = False
        
        self.__set_public_key_path(public_key_path)

    def __check_path(self, path: str, dir_check: bool = False) -> bool:
        print(f"RTX | DEBUG | Encryptor::__check_path(): Checking path '{path}'")

        p = Path(path)

        if not p.exists() or (dir_check and p.is_dir()):
            print(f"RTX | DEBUG | Encryptor::__check_path(): Provided path is invalid: {path}")
            return False
        
        return True

    def __set_public_key_path(self, path: str) -> None:
        if not self.__check_path(path, True):
            return
        
        self.__public_key_path_valid = True
        print(f"RTX | DEBUG | Encryptor::__set_public_key_path(): self.__public_key_path_valid: {self.__public_key_path_valid}")

        self.__public_key_path = path

        return

    def __load_recipient_public_key(self) -> rsa.PublicKey | None:
        print(f"RTX | DEBUG | Encryptor::__load_recipient_public_key(): Loading recipient's public key from '{self.__public_key_path}'")

        txt = b''
        pub = None

        try:
            with open(self.__public_key_path, 'rb') as f:
                txt = f.read()

            pub = rsa.PublicKey.load_pkcs1(txt, format='PEM')
        except FileNotFoundError:
            print("RTX | DEBUG | Encryptor::__load_recipient_public_key(): Public key file not found.")
        except PermissionError:
            print("RTX | DEBUG | Encryptor::__load_recipient_public_key(): No permission to read the public key file.")
        except OSError as e:
            print(f"RTX | DEBUG | Encryptor::__load_recipient_public_key(): OS error while reading: {e}")
        except Exception as e:
            print(f"RTX | DEBUG | Encryptor::__load_recipient_public_key(): Unexpected error: {e}")

        return pub

    def __check_message(self, msg: bytes) -> bool:
        print(f"RTX | DEBUG | Encryptor::__check_message(): Checking message validity")

        if not msg:
            print("RTX | DEBUG | Encryptor::__check_message(): Message is empty.")
            return False

        return True

    def encrypt_message(self, msg: bytes) -> bytes | None:
        print(f"RTX | DEBUG | Encryptor::encrypt_message(): self.__public_key_path_valid: {self.__public_key_path_valid}")
        if not self.__public_key_path_valid:
            print("RTX | DEBUG | Encryptor::encrypt_message(): Public key path is not valid.")
            return None
        
        if not self.__check_message(msg):
            return None

        public_key = self.__load_recipient_public_key()

        encrypted_msg = rsa.encrypt(msg, public_key)

        print("RTX | INFO | Encryptor::encrypt_message(): Mensagem cifrada com sucesso")

        return encrypted_msg
    
    def encrypt_message_to_file(self, msg: bytes, path: str) -> bool:
        encrypted_msg = self.encrypt_message(msg)

        if encrypted_msg is None:
            return False

        print(f"RTX | DEBUG | Encryptor::encrypt_message_to_file(): Writing encrypted message to 'encrypted_message.txt'")

        if not self.__check_path(path):
            return False

        encrypted_msg_file_path = f"{path}/encrypted_message.txt"

        try:
            with open(encrypted_msg_file_path,'wb') as f:
                f.write(encrypted_msg)
        except FileNotFoundError:
            print("RTX | DEBUG | Encryptor::encrypt_message_to_file(): Folder does not exist.")
            return False
        except PermissionError:
            print("RTX | DEBUG | Encryptor::encrypt_message_to_file(): No permission to write here.")
            return False
        except OSError as e:
            print(f"RTX | DEBUG | Encryptor::encrypt_message_to_file(): OS error while writing: {e}")
            return False
        except Exception as e:
            print(f"RTX | DEBUG | Encryptor::encrypt_message_to_file(): Unexpected error: {e}")
            return False
        
        return True
