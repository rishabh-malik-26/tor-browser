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