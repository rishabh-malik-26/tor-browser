from relay_node import RelayNode

if __name__ == '__main__':
    # Relay1 listens on port 9000
    # Relay1 forwards to Relay2 at port 9001
    relay1 = RelayNode(listen_port=9000, next_host='127.0.0.1', next_port=9001,private_key_path=r"relay_private_keys\relay_1_privatekey.pem")
    relay1.run()
