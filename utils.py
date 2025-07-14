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



def symm_encrypt(key, message):
    fernet = Fernet(key)

    # if not isinstance(message, (dict, list)):
    #     raise ValueError("Encrypt layer must be dict or list")
    
    # message_bytes = json.dumps(message).encode()

    if isinstance(message,(list,dict)):
        message_bytes = json.dumps(message).encode()
    elif isinstance(message, str):
        message_bytes = message.encode()
    else:
        message_bytes = message

    logging.info(f"Converted {message} to json:{message_bytes}")
    # message_bytes = message.encode()
    return fernet.encrypt(message_bytes)


def onion(onion_message:str) -> json:

    logging.info(f'Message Data Type: {type(onion_message)}')

    if isinstance(onion_message,str):

    # ## Load Symmetric Keys
        key_1 = load_symm_key(filepath='symmetric_keys\key_1')
        logging.info(f"Key 1{key_1} loaded")
        logging.info(f" Key 1 data type {type(key_1)}")


        key_2 = load_symm_key(filepath='symmetric_keys\key_2')
        logging.info(f"Key 2{key_2} Loaded")
        logging.info(f" Key 2 data type {type(key_2)}")


        key_3 = load_symm_key(filepath='symmetric_keys\key_3')
        logging.info(f"Key 3{key_3} Loaded")
        logging.info(f" Key 3 data type {type(key_3)}")


        ## Encrypts symmentic keys with Assymetric (RSA) keys
        rsa_encrypted_key_1 = rsa_encryption(public_key_path=r"relay_keys\relay_1_publickey.pem", symmetric_key=key_1)
        logging.info(f'1st symmetric key crypted by RSA:{type(rsa_encrypted_key_1)}')
        logging.info(f"RSA 1 key data type: {type(rsa_encrypted_key_1)}")

        rsa_encrypted_key_2 = rsa_encryption(public_key_path=r"relay_keys\relay_2_publickey.pem", symmetric_key=key_2)
        logging.info(f'2nd symmetric key crypted by RSA')
        logging.info(f"RSA 2 key data type: {type(rsa_encrypted_key_2)}")

        rsa_encrypted_key_3 = rsa_encryption(public_key_path=r"relay_keys\relay_3_publickey.pem", symmetric_key=key_3)
        logging.info(f'3rd symmetric key crypted by RSA')
        logging.info(f"RSA 3 key data type: {type(rsa_encrypted_key_3)}")

        inner_layer = {"encrypted_key":rsa_encrypted_key_3,"message":base64.b64encode(symm_encrypt(key=key_3,message=onion_message)).decode()}
        logging.info(f"Inner Layer message:{symm_encrypt(key=key_3,message=onion_message)}")
        logging.info(f"Inner Layer Data type: {type(inner_layer)}")

        middle_layer =  {"encrypted_key":rsa_encrypted_key_2,"message":base64.b64encode(symm_encrypt(key=key_2,message=inner_layer)).decode()}
        logging.info(f"Middle Layer message:{symm_encrypt(key=key_2,message=inner_layer)}")
        logging.info(f"Middle Layer Data type: {type(middle_layer)}")

        outer_layer = {"encrypted_key":rsa_encrypted_key_1,"message":base64.b64encode(symm_encrypt(key=key_1,message=middle_layer)).decode()}
        logging.info(f"Outer Layer Message {symm_encrypt(key=key_1,message=inner_layer)}")
        logging.info(f"Outer Layer Data type: {type(outer_layer)}")

        json_output = json.dumps(outer_layer)
        logging.info(f' Outer Layer Converted to json:{json_output}')
        logging.info(f"Final Output Layer Datatype: {type(json_output)}")

        return json_output
    
    else:
        raise ValueError('Message is not a valid data type, It should be string')

def load_symm_key(filepath:str) -> bytes:
    """Loads Symmetric keys from their file path"""

    if isinstance(filepath,str):
        try:
            with open( filepath,"rb") as f:
                    logging.info(f'Symmetric key File opened: {filepath}')
                    key= f.read()
                    if not key:
                        logging.warning(f"Symmetric key file {filepath} is empty.")
                    else:
                        logging.info(f'Symmetric key read')
                        logging.info(f'Key data type: {type(key)}')
                        return key
                    
        except FileNotFoundError as e:
            logging.error(f'Error Opening {filepath}:{e}')
            raise
    else:
        raise ValueError(f"Filepath is not a valid datatype")


