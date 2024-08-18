import argparse
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, salt: bytes) -> bytes:
    """Deriva una clave usando PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requiere una clave de 32 bytes
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str) -> str:
    """Encripta un archivo usando AES-256 y una clave derivada de la contraseña proporcionada."""
    salt = os.urandom(16)  # Genera un salt aleatorio
    key = derive_key(password, salt)
    
    # Genera un IV (Initial Vector) de 16 bytes
    iv = os.urandom(16)
    
    # Configura el cifrador AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Lee el contenido del archivo
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Aplica padding al contenido del archivo para que sea múltiplo de 128 bits
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Encripta los datos
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Escribe el archivo encriptado con el salt y el iv prepended
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)
    
    # Elimina el archivo original
    os.remove(file_path)
    
    return encrypted_file_path

def decrypt_file(file_path: str, password: str) -> str:
    """Desencripta un archivo encriptado con la función encrypt_file."""
    with open(file_path, 'rb') as f:
        salt = f.read(16)  # Lee el salt (los primeros 16 bytes)
        iv = f.read(16)    # Lee el IV (los siguientes 16 bytes)
        encrypted_data = f.read()  # Lee los datos encriptados restantes
    
    key = derive_key(password, salt)
    
    # Configura el descifrador AES en modo CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Desencripta los datos
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Elimina el padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    # Escribe los datos desencriptados en un nuevo archivo
    decrypted_file_path = file_path[:-4]  # Remueve la extensión '.enc'
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
    
    # Elimina el archivo encriptado original
    os.remove(file_path)
    
    return decrypted_file_path

def encrypt_directory(directory: str, password: str):
    """Encripta recursivamente todos los archivos dentro de un directorio."""
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            encrypted_file = encrypt_file(file_path, password)
            print(f"Archivo encriptado: {encrypted_file}")

def decrypt_directory(directory: str, password: str):
    """Desencripta recursivamente todos los archivos encriptados dentro de un directorio."""
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                decrypted_file = decrypt_file(file_path, password)
                print(f"Archivo desencriptado: {decrypted_file}")

def main():
    parser = argparse.ArgumentParser(description="Encripta o desencripta archivos o directorios usando AES-256.")
    parser.add_argument('-a', '--encrypt', type=str, help="Archivo o directorio a encriptar")
    parser.add_argument('-s', '--decrypt', type=str, help="Archivo o directorio a desencriptar")
    parser.add_argument('-p', '--password', type=str, required=True, help="Contraseña para encriptar/desencriptar")
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')

    args = parser.parse_args()

    if args.encrypt:
        if os.path.isdir(args.encrypt):
            encrypt_directory(args.encrypt, args.password)
        else:
            encrypted_file = encrypt_file(args.encrypt, args.password)
            print(f"Archivo encriptado: {encrypted_file}")

    elif args.decrypt:
        if os.path.isdir(args.decrypt):
            decrypt_directory(args.decrypt, args.password)
        else:
            decrypted_file = decrypt_file(args.decrypt, args.password)
            print(f"Archivo desencriptado: {decrypted_file}")

    else:
        print("Por favor, utiliza -a para encriptar o -s para desencriptar un archivo o directorio.")
        parser.print_help()

if __name__ == "__main__":
    main()
