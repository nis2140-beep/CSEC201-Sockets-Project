import rsa

# --------------------------------------------- ! functions will be later integrated into the client and server files ! ---------------------------------------------

# -------SERVER

# 1
# generates RSA public and private keys
# public key will be sent to client

# 3
# receives the session key from the client, decrypts using the private rsa key ---> used late in operation


# -------CLIENT

# 2
#  generates a session key
#  encrypts said session key using the SERVER's public rsa key
#  session key sent to server



# this should be place on the top of both client and server files
def create_rsa_keys(): # creating the RSA public and private keys
    public_key, private_key = rsa.newkeys(1024)
    
    return public_key, private_key # returns keys: public, private --> returns as a looooong tuple

public_rsa, private_rsa = create_rsa_keys() # unpacking the tuple and separating the two keys as two different variables

# after this, update the part on the server so there is a new elif branch for if the client selects "1" ---> server will send CC + server public key 

# client will send encryption packet to server: [<paclet type>, <algorithm>, <session key>, username:<CLIENT pub key>]
# session_key is ENCRYPTED using rsa key from the server

def encrypt_rsa(message, server_public_rsa): #takes two arguments i.e. session_key and the server_public_key
    encrypted = rsa.encrypt(message.encode(), server_public_rsa) # encrypts it
    return encrypted

#decrypting (for the server)
def decrypt_rsa(encrypted, server_private_key):
    decrypted = rsa.decrypt(encrypted, server_private_key)
    return decrypted
    
    




#  -------------------------------------------------- ! TESTING GROUNDS ! ----------------------------------------------------- 

# # testing the generate rsa keys
# print( "c'est public key: ", public_rsa)
# print("c'est private key: ", private_rsa)
# print(type(public_rsa)) # prints what type of key
# print(public_rsa.save_pkcs1()) # serializes the key...? ---> turns into bytes


# # testing the encrypt and decrypt
# test = "goodnight <3"
# server_pub = public_rsas
# # print(encrypt_rsa(test, server_pub)) # YEAHHHH IT WORKS
# secret = encrypt_rsa(test, server_pub)

# server_priv = private_rsa
# unsecret = decrypt_rsa(secret, server_priv)

# print("ENCRYPTED: ", secret)
# print("DECRYPTED: ",unsecret) # IT WORKSSSSS



    




