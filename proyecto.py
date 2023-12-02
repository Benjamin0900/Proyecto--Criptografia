from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

iv = urandom(16)  # El tamaño del IV depende del algoritmo de cifrado utilizado

def generar_par_claves_rsa():
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def generar_par_claves_ecc():
    clave_privada = ec.generate_private_key(
        ec.SECP256R1(),  # Puedes elegir una curva diferente si es necesario
        backend=default_backend()
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica

def cifrar_rsa(mensaje, clave_publica):
    texto_cifrado = clave_publica.encrypt(
        mensaje,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return texto_cifrado

def descifrar_rsa(texto_cifrado, clave_privada):
    texto_plano = clave_privada.decrypt(
        texto_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return texto_plano

def cifrar_ecc(mensaje, clave_publica, clave_privada):
    clave_compartida = clave_privada.exchange(ec.ECDH(), clave_publica)
    # Usa la clave_compartida para derivar una clave simétrica y cifrar el mensaje.
    clave_compartida_bytes = int.from_bytes(clave_compartida, 'big').to_bytes(32, 'big')  # Suponiendo un tamaño de clave de 256 bits
    cifrador = Cipher(algorithms.AES(clave_compartida_bytes), modes.CFB(iv), backend=default_backend())
    cifrador_aes = cifrador.encryptor()
    texto_cifrado = cifrador_aes.update(mensaje) + cifrador_aes.finalize()
    return texto_cifrado

def descifrar_ecc(texto_cifrado, clave_privada, clave_publica):
    clave_compartida = clave_privada.exchange(ec.ECDH(), clave_publica)
    # Usa la clave_compartida para derivar una clave simétrica y descifrar el mensaje.
    clave_compartida_bytes = int.from_bytes(clave_compartida, 'big').to_bytes(32, 'big')  # Suponiendo un tamaño de clave de 256 bits
    cifrador = Cipher(algorithms.AES(clave_compartida_bytes), modes.CFB(iv), backend=default_backend())
    cifrador_aes = cifrador.decryptor()
    texto_plano = cifrador_aes.update(texto_cifrado) + cifrador_aes.finalize()
    return texto_plano

# Uso de ejemplo:
clave_privada_rsa, clave_publica_rsa = generar_par_claves_rsa()
clave_privada_ecc, clave_publica_ecc = generar_par_claves_ecc()

mensaje = b"La temperatura es de 25 grados celcius"

# Cifrar con RSA
texto_cifrado_rsa = cifrar_rsa(mensaje, clave_publica_rsa)
print(f"RSA Cifrado: {texto_cifrado_rsa.hex()}")

# Cifrar con ECC
texto_cifrado_ecc = cifrar_ecc(texto_cifrado_rsa, clave_publica_ecc, clave_privada_ecc)
print(f"ECC Cifrado: {texto_cifrado_ecc.hex()}")

# Descifrar con ECC
texto_cifrado_descifrado = descifrar_ecc(texto_cifrado_ecc, clave_privada_ecc, clave_publica_ecc)

# Descifrar con RSA
texto_final_descifrado = descifrar_rsa(texto_cifrado_descifrado, clave_privada_rsa)
print(f"Texto Final Descifrado: {texto_final_descifrado}")



