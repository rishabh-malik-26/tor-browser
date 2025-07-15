from relay_node import RelayNode

if __name__ == '__main__':
    relay3 = RelayNode(listen_port=9002, is_exit=True,private_key_path=r"relay_private_keys\relay_3_privatekey.pem")
    relay3.run()
