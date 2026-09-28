
# SERVER

# 1
# generates RSA public and private keys
# public key will be sent to client

# 3
# receives the session key from the client, decrypts using the private rsa key ---> used late in operation


# CLIENT

# 2
#  generates a session key
#  encrypts said session key using the SERVER's public rsa key
#  session key sent to server

def create_rsa_keys():
    




