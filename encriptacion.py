from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from colorama import Fore, init

def encriptacion_texto(key, plaintext):
    cifrar = AES.new(key, AES.MODE_EAX)
    texto_descifrado, tag = cifrar.encrypt_and_digest(plaintext.encode('utf-8'))
    return texto_descifrado, tag, cifrar.nonce

def descifrar_texto(key, ciphertext, tag, nonce):
    cifrar = AES.new(key, AES.MODE_EAX, nonce=nonce)
    texto_descifrado = cifrar.decrypt_and_verify(ciphertext, tag)
    return texto_descifrado.decode('utf-8')

def main():
    init()
    # Generar una clave aleatoria de 256 bits
    key = get_random_bytes(32)

    # Texto original
    texto = input("Ingrese el texto a cifrar: ")
    
    # Encriptar el texto
    ciphertext, tag, nonce = encriptacion_texto(key, texto)
    print(Fore.BLUE + f'Texto cifrado: {ciphertext.hex()}')
    print(Fore.BLUE + f'Tag: {tag.hex()}')
    print(Fore.BLUE + f'Nonce: {nonce.hex()}')

    # Desencriptar el texto
    texto_descriptivo = descifrar_texto(key, ciphertext, tag, nonce)
    print(Fore.GREEN + f'Texto descifrado: {texto_descriptivo}')

if __name__ == "__main__":
    main()
