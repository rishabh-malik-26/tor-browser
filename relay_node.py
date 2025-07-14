
from sockets import Socket
import logging
from utils import relay_decrypt
logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')

class RelayNode:
    def __init__(self, listen_port , next_host=None, next_port= None,is_exit= False,private_key_path=None):
        self.server = Socket()
        self.is_exit = is_exit
        self.listen_port = listen_port
        self.private_key_path = private_key_path
        if not is_exit:
            self.client = Socket()
            self.listen_port = listen_port
            self.next_host = next_host
            self.next_port = next_port

    def run(self):
        while True:
            incoming_message = self.server.receive(port=self.listen_port, host='127.0.0.1')
            logging.info(f'Data received')
            print(f"Relay received: {incoming_message}")

            decrypted_message = relay_decrypt(message=incoming_message,private_key_path=self.private_key_path)
            logging.info(f"Message Decrypted:{decrypted_message}")

            if self.is_exit():
                self.forward_to_internet(decrypted_message=decrypted_message)

            else:
                self.client.send(port=self.next_port, host=self.next_host, message=decrypted_message)
                logging.info(f'{decrypted_message} Shared to {self.next_port}')

    def forward_to_internet(self, decrypted_message):
        import requests
        response = requests.get("https://duckduckgo.com/", params={"q": decrypted_message})
        print(response.content)



