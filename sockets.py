import socket
import logging
logging.basicConfig(level=logging.INFO,format='%(asctime)s -%(levelname)s - %(message)s' )

host= "127.0.0.1"

class Socket():
    def __init__(self):
        try:   
            self.socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            logging.info(f'Socket Created')
        except Exception as e:
            logging.error(f"Error creating Socker:{e}")
        
    def receive(self,port,host):
        try:
            self.socket.bind((host,port))
            logging.info(f"Socket binded to {port}")

            self.socket.listen(5)
            logging.info(f'{self.socket} is Listening')  

            while True:
                conn,addr = self.socket.accept()
                logging.info(f"Got connection from, {addr}")

                received_bytes = conn.recv(1024)
                logging.info(f'Message received as bytes :{type(received_bytes)}')
                logging.info(f'Data type of Message received :{type(received_bytes)}')

                decoded_message  = received_bytes.decode()
                logging.info(f'Message decoded as json :{decoded_message}')
                logging.info(f'Data type of Message encoded :{type(decoded_message)}')

                conn.close()
                logging.info(f"Connection Closed")
                # break
                return decoded_message
        except Exception as e:
            logging.info(f'Error Creating Socket:{e}')
            self.socket.close()
            raise
 
    def send(self,port,host,message):
        try:
            self.socket.connect((host,port))
            msg = self.socket.send(message.encode())
            self.socket.close()
            logging.info(f"Message sent:{msg}")
        except Exception as e:
            logging.error(f"Error sending message: {e}")



