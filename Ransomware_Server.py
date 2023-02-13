import socketserver
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

class ClientHandler(socketserver.BaseRequestHandler):

   def handle(self):
        encrypted_key = self.request.recv(1024).strip()
        print ("Implement decryption of data " + encrypted_key )

        #beggining of my code
        with open("./keys/pub_priv_pair.key", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
               key_file.read(),
               password=None,
               backend=default_backend()
         )

      #Encrypts my the public key with the symmertic key
        decryptedSymmetricKey = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
               mgf=padding.MGF1(algorithm=hashes.SHA256()),
               algorithm=hashes.SHA256(),
               label=None          
         )   
  
      ) 
        self.request.sendall("send key back")
if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 5001

tcpServer =  socketserver.TCPServer((HOST, PORT), ClientHandler)
try:
   tcpServer.serve_forever()
except:
   print("There was an error")