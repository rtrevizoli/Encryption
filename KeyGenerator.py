import rsa
import argparse
from pathlib import Path

print ('\\-------------------------------//')
print (' **Gerador de chaves assimetricas** ')
print (' \\-------------------------------//')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=str, help="Absolute or relative filesystem path for key generation.")
    parser.add_argument("--key-name", type=str, help="String for naming the generated key files.")
    parser.add_argument("--size", type=int, help="Size of the key to be generated in bits.")
    args = parser.parse_args()

    data = handle_args(vars(args))

    if not check_path(data['path'], data['key_name']):
        return

    (public, private) = generate_key_pair(data['size'])

    write_key_to_file(public, data['path'], data['key_name'])
    write_key_to_file(private, data['path'], data['key_name'])

    print(public.save_pkcs1(format='PEM').decode())

    return

def handle_args(data: dict[str, any]) -> dict[str, any]:
    print(f"RTX | DEBUG | KeyGenerator::handle_args(): Data before handling: {data}")

    # check_path()
    if data['path'] is None:
        data['path'] = './'

    # check_key_name()
    if data['key_name'] is None:
        data['key_name'] = 'mykey'

    # check_size()
    if data['size'] is None:
        data['size'] = 2048

    print(f"RTX | DEBUG | KeyGenerator::handle_args(): Data after handling: {data}")
    return data

def check_path(path: str, key_name: str) -> None:
    print(f"RTX | DEBUG | KeyGenerator::check_path(): Checking path '{path}' for key name '{key_name}'")
    
    p = Path(path)

    if not p.exists():
        path.mkdir(parents=True, exist_ok=True)
        return True

    if p.is_file():
        print(f"RTX | DEBUG | KeyGenerator::check_path(): Provided path is a file, not a directory. {path}")
        return False
    
    public_key_path = Path(get_key_file_path(path, key_name, True))
    public_key_path = Path(get_key_file_path(path, key_name, False))

    if public_key_path.exists() or public_key_path.exists():
        answer = input(f"Key file already exists at {path}. Do you want to overwrite ? [y/N]: ").strip().lower()

        if answer not in ("y", "yes"):
            print("RTX | DEBUG | KeyGenerator::write_key_to_file(): Key generation aborted by user.")
            return False

    return True

def generate_key_pair(size: int) -> tuple[rsa.PublicKey, rsa.PrivateKey]:
    print(f"RTX | DEBUG | KeyGenerator::generate_key_pair(): Generating key pair of size {size} bits")
    return rsa.newkeys(int(size))

def write_key_to_file(key: rsa.key, path: str, key_name: str) -> None:
    key_file_path = get_key_file_path(path, key_name, isinstance(key, rsa.PublicKey))

    try:
        #codifico o exponente e modulo da chave para o formate PEM
        with open(key_file_path,'wb') as f:
            f.write(key.save_pkcs1(format='PEM'))
    except FileNotFoundError:
        print("RTX | DEBUG | KeyGenerator::write_key_to_file(): Folder does not exist.")
    except PermissionError:
        print("RTX | DEBUG | KeyGenerator::write_key_to_file(): No permission to write here.")
    except OSError as e:
        print(f"RTX | DEBUG | KeyGenerator::write_key_to_file(): OS error while writing: {e}")
    except Exception as e:
        print(f"RTX | DEBUG | KeyGenerator::write_key_to_file(): Unexpected error: {e}")

def get_key_file_path(path: str, key_name: str, is_public: bool) -> str:
    ext = "pub" if is_public else "pri"
    return f"{path}/{key_name}-{ext}.txt"

if __name__ == "__main__":
    main()
