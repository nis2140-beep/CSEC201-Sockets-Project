import rsa
import os

# --------------------------------------------- ! functions will be later integrated into the client and server files ! ---------------------------------------------

# -------SERVER

# 1
# generates RSA public and private keys  ------> https://youtu.be/n0uJsqFGO4k?si=OYMQTLvJ7u9tnWgS
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
    public_key, private_key = rsa.newkeys(2048) #changed from 1024 -> 2048
    
    return public_key, private_key # returns keys: public, private --> returns as a looooong tuple
public_rsa, private_rsa = create_rsa_keys() # unpacking the tuple and separating the two keys as two different variables

# after this, update the part on the server so there is a new elif branch for if the client selects "1" ---> server will send CC + server public key 

# client will send encryption packet to server: [<packet type>, <algorithm>, <session key>, username:<CLIENT pub key>]
# session_key is ENCRYPTED using rsa key from the server

def create_session_key(): # FOR CLIENT: generates and returns a random number of bytes --> in this case, 16 random bytes 
    session_key = os.urandom(16)
    return session_key  

def encrypt_rsa(session_key, server_public_rsa): # FOR CLIENT: takes two arguments i.e. session_key and the server_public_key
    encrypted = rsa.encrypt(session_key, server_public_rsa) # encrypts it
    return encrypted #returns the ecrypted session key

#decrypting (for the server)
def decrypt_rsa(encrypted, server_private_key): #FOR SERVER: takes the encrypted session key and the server's own private key
    decrypted = rsa.decrypt(encrypted, server_private_key) #decrypts the session key from the client
    return decrypted # returns the decrypted session key



    
    




#  -------------------------------------------------- ! TESTING GROUNDS ! ----------------------------------------------------- 

# # testing the generate rsa keys
# print( "c'est public key: ", public_rsa)
# print("c'est private key: ", private_rsa)
# print(type(public_rsa)) # prints what type of key
# print(public_rsa.save_pkcs1()) # serializes the key...? ---> turns into bytes


# # testing the encrypt and decrypt
# test = "goodnight <3"
# server_pub = public_rsa
# # print(encrypt_rsa(test, server_pub)) # YEAHHHH IT WORKS
# secret = encrypt_rsa(test, server_pub)

# server_priv = private_rsa
# unsecret = decrypt_rsa(secret, server_priv)

# print("ENCRYPTED: ", secret)
# print("DECRYPTED: ",unsecret) # IT WORKSSSSS



# # testing encrypt and decrypt with the session key
# #CLIENT
# key = create_session_key()
# print("session key pre-encryption: ", key)
# encrypted = encrypt_rsa(key, public_rsa)
# print("session key post-encryption: ", encrypted)

# #SERVER
# decrypted = decrypt_rsa(encrypted, private_rsa)
# print("session key, post decryption: ", decrypted) #IT WORKSSSS






    




