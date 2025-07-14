import logging
logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s',filename="logs.log")
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.fernet import Fernet
import json
import base64

def receive_data(socket_name,port,host):

        try:
            # socket_name.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            socket_name.bind((host,port))
            logging.info(f"Socket binded to {port}")

            socket_name.listen(5)
            logging.info(f'{socket_name} is Listening')  

            while True:
                conn,addr = socket_name.accept()
                logging.info(f"Got connection from, {addr}")

                message = conn.recv(1024).decode()
                logging.info(f'Message received and decoded :{message}')

                conn.close()
                logging.info(f"Connection Closed")
                # break
                return message
        except Exception as e:
            logging.info(f'Error Creating Socket:{e}')
            raise



def send(socket_name:str,port:int,host,message:str):
    try:
       socket_name.connect((host, port))
       logging.info(f'Socket Connected to Host:{host}, Port:{port}')

       try:
        logging.info(f'message datatype before encoding: {type(message)}')

        encoded_message = message.encode()
        logging.info(f'Data Type of message after encoding: {type(encoded_message)}')

        msg = socket_name.send(encoded_message)
        # logging.info(f'message datatype: {type(message)}')
        logging.info(f"Message sent:{msg}")

       except Exception as e:
           logging.error(f'Error Sending Message')
           raise

    except Exception as e:
        logging.error(f"Error sending message: {e}")
        raise


def symm_key(filename:str) -> bytes:
    # Creates Symmetric Keys
    key = Fernet.generate_key()
    logging.info(f'Symmetric Key Generated')
    with open(f"symmetric_keys/{filename}","wb") as f:
        f.write(key)
    return key



def symm_decrypt(key:bytes, encrypted_data):
    fernet = Fernet(key)
    decrypted_bytes = fernet.decrypt(encrypted_data)
    # message = json.loads(decrypted_bytes.decode())
    return decrypted_bytes


def rsa_encryption(public_key_path:str,symmetric_key:bytes) -> bytes:
    ## Load Public RSA key
    if isinstance(symmetric_key, bytes):
        try:
            with open(public_key_path,"rb") as f:
                logging.info(f'Public RSA file opened')
                public_key = serialization.load_pem_public_key(f.read())
                logging.info(f'Public key loaded of path{public_key}')
    
                if not public_key:
                    logging.error(f'Public RSA key not found for file: {public_key_path}')
                
                else:
                    logging.info(f'Public RSA key data type: {type(public_key)}')

                    encoded_symmetric_key = symmetric_key.encode()

                    logging.info(f'Symmetric key encoded')

                    ## Encrypt Message/Key with RSA Key
                    encryped_message = public_key.encrypt(encoded_symmetric_key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            ))
                    
                    logging.info(f'Encrypted: symmetric encrypted with RSA')

                    decoded_encrypted_message = base64.b64encode(encryped_message).decode()
                    logging.info(f'Decoded: message encrypted with RSA')
                    logging.info(f'RSA encrypted symmteric key datatype:{type(decoded_encrypted_message)}')
                    
                    return decoded_encrypted_message
        except FileNotFoundError as f:
            logging.error(f'Error Opening file:{public_key},error:{f}')
            raise 

    else:
        raise ValueError(f'Message is not bytes')
