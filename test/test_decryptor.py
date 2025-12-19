
import argparse
from decryptor.decryptor import Decryptor

print ('\\-------------------------------//')
print ('    **Decifrador de mensagens**   ')
print ('\\-------------------------------//')

# python -m test.test_decryptor --private-key-path ./mykey-pri.txt --encrypted-msg-path ./encrypted_message.txt

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key-path", type=str, required=True, help="Absolute or relative path for recipient's publict key.")
    parser.add_argument("--encrypted-msg-path", type=str, required=True, help="Absolute or relative path for encrypted message to be decrypted.")
    args = parser.parse_args()

    data = vars(args)

    decryptor = Decryptor(data['private_key_path'])

    test_decrypt_message(decryptor, decryptor.load_file_content(data['encrypted_msg_path']))

def test_decrypt_message(decryptor: Decryptor, msg: str) -> None:
    decrypted = decryptor.decrypt_message(msg)

    if not decrypted:
        print("RTX | ERROR | main(): Decryption failed")
        return

    print(f"RTX | INFO | main(): Decripted successfully\n {decrypted}")

if __name__ == "__main__":
    main()
