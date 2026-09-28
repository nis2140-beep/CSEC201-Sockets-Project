import rsa

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


def create_rsa_keys(): # creating the RSA public and private keys
    public_key, private_key = rsa.newkeys(1024)
    
    return public_key, private_key # returns keys: public, private --> returns as a looooong tuple

public_rsa, private_rsa = create_rsa_keys() # unpacking the tuple and separating the two keys as two different variables

# TESTING GROUNDS
# print( "c'est public key: ", public_rsa)
# print("c'est private key: ", private_rsa)
# print(type(public_rsa)) # prints what type of key
# print(public_rsa.save_pkcs1()) # serializes the key...? ---> turns into bytes


    




