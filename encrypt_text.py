from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_keys():
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

  
    public_key = private_key.public_key()

    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

   
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def encrypt_message(public_pem, message):
    
    public_key = serialization.load_pem_public_key(public_pem)

    
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_message

def decrypt_message(private_pem, encrypted_message):
    
    private_key = serialization.load_pem_private_key(private_pem, password=None)

    
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_message.decode()

if __name__ == "__main__":
  
    private_pem, public_pem = generate_keys()

    
    print("Private Key:", private_pem.decode())
    print("Public Key:", public_pem.decode())

   
    message = input("Enter the message you want to encrypt: ")

    
    encrypted_message = encrypt_message(public_pem, message)
    print("Encrypted Message:", encrypted_message)

    
    decrypt_option = input("Do you want to decrypt the message? (yes/no): ")
    if decrypt_option.lower() == 'yes':
        decrypted_message = decrypt_message(private_pem, encrypted_message)
        print("Decrypted Message:", decrypted_message)
