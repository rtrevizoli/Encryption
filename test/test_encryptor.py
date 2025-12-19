import argparse
from encryptor.encryptor import Encryptor

print ('\\-------------------------------//')
print ('     **Cifrador de mensagens**     ')
print ('\\-------------------------------//')

# python -m test.test_encryptor --public-key-path ./mykey-pub.txt --msg "Hello World"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key-path", type=str, required=True, help="Absolute or relative path for recipient's publict key.")
    parser.add_argument("--msg", type=str, required=True, help="Message to be encrypted.")
    parser.add_argument("--output-path", type=int, help="Absolute or relative path for saving the encrypted message.")
    args = parser.parse_args()

    data = vars(args)

    encryptor = Encryptor(data['public_key_path'])

    test_encrypt_message(encryptor, data['msg'])

    test_encrypt_message_to_file(encryptor, data['msg'], data['output_path'] if data['output_path'] else './')

def test_encrypt_message(encryptor: Encryptor, msg: str) -> None:
    encrypted = encryptor.encrypt_message(msg.encode('utf-8'))

    if not encrypted:
        print("RTX | ERROR | main(): Encryption failed")
        return

    print(f"RTX | INFO | main(): Encrypted successfully\n {encrypted}")

def test_encrypt_message_to_file(encryptor: Encryptor, msg: str, path: str) -> None:
    success = encryptor.encrypt_message_to_file(msg.encode('utf-8'), path)

    if not success:
        print("RTX | ERROR | main(): Encryption to file failed")
        return

    print("RTX | INFO | main(): Encrypted to file successfully")

if __name__ == "__main__":
    main()
