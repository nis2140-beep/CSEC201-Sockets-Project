import rsa
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes #from claude, for the AES cipher

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
    #session_key = os.urandom(32)
    return session_key  

def encrypt_rsa(session_key, server_public_rsa): # FOR CLIENT: takes two arguments i.e. session_key and the server_public_key
    encrypted = rsa.encrypt(session_key, server_public_rsa) # encrypts it
    return encrypted #returns the ecrypted session key

#decrypting (for the server)
def decrypt_rsa(encrypted, server_private_key): #FOR SERVER: takes the encrypted session key and the server's own private key
    decrypted = rsa.decrypt(encrypted, server_private_key) #decrypts the session key from the client
    return decrypted # returns the decrypted session key






# AES is used to lock all the files that get transferred between server and client; session_key is used as a key for the AES cipher
def encrypt_aes(file_content, session_key): #takes the file that is to be encrypted via aes, and uses the session_key as a key for the cipher
   
    iv = os.urandom(16) #----> initialization vector, makes it so that whatever is being encrypted doesn't transform into the same ciphertext when encrypted multiple times; randomizes the ciphertext content-ish
   
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv)) 
    # ----> basically: use AES with session_key as the key, run it in CFB mode (starting from iv), wrapped all into Cipher(...) to turn algorithm and mode into 1 object
   
    encryptor = cipher.encryptor() #---> this is the object that turns the normal text into ciphertext
    
    ciphertext = encryptor.update(file_content) + encryptor.finalize()
    # ----> tells the encryptor to get to work encrypting (gives the file_content to the encryptor) + signals encryptor that the content is done, returns leftover bytes 
    # combined into one ciphertext (encrypted result)
    
    return iv + ciphertext  # gives the EXACT SAME IV for the decryptor + the ciphertext/encrypted result
    
    
    
def decrypt_aes(encrypted_file, session_key): # takes the encrypted file, uses the session_key as, well, the key for AES cipher
    iv = encrypted_file[:16] #----> slices the AES encrypted file to take the iv only
    ciphertext = encrypted_file[16:] # ----> slices to take everything after the iv as the encrypted ciphertext
    
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv)) 
    # ----> basically: use AES with session_key as the key, run it in CFB mode (starting from iv), wrapped all into Cipher(...) to turn algorithm and mode into 1 object
    # essentially setting up the AES
    
    decryptor = cipher.decryptor() #----> the object that actually turns the ciphertext into normal text
    
    decrypted_file = decryptor.update(ciphertext) + decryptor.finalize() 
    # ---> reverse of the encryptor one 
    # tells the decryptor to get to work on the ciphertext + tells decryptor khalas and to return any leftover bytes
    
    return decrypted_file #boom file decrypted 
    

# UP NEXT: 
# ADD THE CAESAR FUNCTION RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# -> integrate RSA functions into both client and server, check if the transfer works properly between client and server
# --> then integrate the AES cipher into the client and server files
# ---> combine the RSA + AES to work for the packets

def encrypt_caesar(file_content, shift): #takes STRING, uses shift (session_key) for the cipher
    res = "" # caesar-encrypted text will end up here
    for char in file_content: # loops through the whole file
        if char.isalpha(): #checks if char is a letter (true), false if spaces or numbers or punctuation
            base = ord('A') if char.isupper() else ord('a') #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            # ord() turns the letter into the numerical representation, puts it into base
            
            res += chr((ord(char) - base + shift) % 26 + base) #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        else:
            res += char #goes here if the char isn't a letter, leaves it alone
    
    return res

def decrypt_caesar(encrypted_file, shift):
    return encrypt_caesar(encrypted_file, -shift) #calls the encryption function but -shift so it goes backwards

    
            
        
        
        
    
    







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






# # testing the AES encryption stuff
# code = create_session_key()

# str = "kinda hungry ngl"
# msg = str.encode() # needs to be bytes in order for the whole aes process to work

# encrypted_msg = encrypt_aes(msg, code)
# decrypted_msg = decrypt_aes(encrypted_msg, code)

# print("THE MESSAGE AS BYTES: ", decrypted_msg) #returns as bytes though --> bc of .encode()
# print("THE MESSAGE AS STRING: ", decrypted_msg.decode()) #.decode() turns it back to string




# testing the rsa/aes relationship thingy "( - ⌓ - )

# 1. server and client generate their own rsa key pairs
# 2. server sends its public key to client
# 3. client creates session key
# 4. client encrypts session key via rsa
# 5. client sends encrypted session key to server
# 6. server decrypts session key
# 7. session key is then used for AES 

# #SERVER ---> rsa keys already generated up there^^
# server_pb_key = public_rsa # js for the simulation, assume its a different public key from the client's

# #CLIENT
# session_key = create_session_key()

# #--> receives the server's public key, rsa encrypt's the session key w it, sends to server after
# encrypted_key = encrypt_rsa(session_key, server_pb_key)

# #SERVER
# CL_session_key = decrypt_rsa(encrypted_key, private_rsa)
# print(session_key == CL_session_key) # true == worked

# message = "use your imagination".encode()

# encrypted_file = encrypt_aes(message, CL_session_key)
# print("encrypted file: ", encrypted_file)

# decrypted_file = decrypt_aes(encrypted_file, CL_session_key)
# print("decrypted file: ", decrypted_file.decode())




# testing the caesar cipher
