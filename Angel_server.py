import socket
import base64
import binascii
import os
import threading
import rsa

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def create_rsa_keys(): # creating the RSA public and private keys
    public_key, private_key = rsa.newkeys(2048) #changed from 1024 -> 2048
    
    return public_key, private_key # returns keys: public, private --> returns as a looooong tuple

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

# caesar cipher just swaps the letters around based on a shift; the session_key will act as the shift here
def encrypt_caesar(file_content, shift): #takes STRING, uses shift (session_key) for the cipher
    res = "" # caesar-encrypted text will end up here
    for char in file_content: # loops through the whole file
        if char.isalpha(): #checks if char is a letter (true), false if spaces or numbers or punctuation
            
            base = ord('A') if char.isupper() else ord('a') 
            # ord() turns the letter into the numerical representation, puts it into base
            # A/a --> starting points
            
            res += chr((ord(char) - base + shift) % 26 + base) 
            # chr() does the oppposite of ord(), turns a number into the letter representation
            # (ord(char) - base) --> gets the position of the letter on the alphabet (0-25)
            # + shift -------------> the shifting part of the caesar cipher, moves it (shift) number of times
            # % 26 ----------------> if the result from (ord(char) - base + shift) is OVER 25
            # + base --------------> turns the result back into a real character code
            
        else:
            res += char #goes here if the char isn't a letter, leaves it alone
    return res

def decrypt_caesar(encrypted_file, shift):
    return encrypt_caesar(encrypted_file, -shift) #calls the encryption function but -shift so it goes backwards


# Creating the listening socket
host = "127.0.0.1"
port = 8888

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host,port))
server_socket.listen(5)

print("RFMP server is listening on port", port)

def client_handler(client_socket, address, client_reader):
    print("Client is connected:", address)

    # Start-Packet (client to server) (Set-up phase)
    message = client_reader.readline()
    if message == "":
        return
    message = message.strip()
    print("Client sent: ", message)
    
    fields = message.split(",")
    
    if fields == ["SS", "RFMP", "v1.0", "0"]:
        client_socket.sendall("CC\n".encode("utf-8"))
        print("Unsecured connection confirmed")
        
        # Setting the client's starting folder
        current_dir = os.path.dirname(os.path.abspath(__file__))
        print("Starting folder:", current_dir)
        
        
        # Keeping client connected until "End"
        for next_packet in client_reader:
            next_packet = next_packet.strip()
            
            if next_packet == "End":
                print("Client has ended the session")
                break
                
            if next_packet.startswith("CM,openRead,"):
                file_name = next_packet.split(",",2)[2]
                print("File requested:", file_name)
                try:
                    with open(os.path.join(current_dir, file_name), "rb") as file:
                        file_content = file.read()

                    encoded_file_content = base64.b64encode(file_content).decode("ascii")
                    client_socket.sendall(("DP," + encoded_file_content + "\n").encode("utf-8"))
                    client_socket.sendall(b"SC,Read complete\n")

                except FileNotFoundError:
                    client_socket.sendall(b"EE,1,File not found\n")
                except OSError:
                    client_socket.sendall(b"EE,3,File could not be read\n")

            elif next_packet.startswith("CM,openWrite,"):
                file_name = next_packet.split(",", 2)[2]
                print("The file to write:", file_name)
                
                data_packet = client_reader.readline()
                if data_packet == "":
                    return

                data_packet = data_packet.strip()
                if data_packet == "End":
                    print("Client has ended the session")
                    return
                if not data_packet.startswith("DP,"):
                    client_socket.sendall(b"EE,2,Expected data packet\n")
                    continue
                try:
                    file_content = base64.b64decode(data_packet[3:], validate=True)
                    
                    with open(os.path.join(current_dir, file_name), "wb") as output_file:
                        output_file.write(file_content)
                        
                except (binascii.Error, ValueError):
                    client_socket.sendall(b"EE,2,Data packet is invalid\n")
                except OSError:
                    client_socket.sendall(b"EE,3,The file could not be written\n")
                else:
                    client_socket.sendall(b"SC,Write is complete\n")
                    
            elif next_packet.startswith("CM,prompt,"):
                prompt_command = next_packet.split(",", 2)[2]
                
                if prompt_command.startswith("mkdir "):
                    folder_name = prompt_command[6:].strip()
                    
                    try:
                        os.mkdir(os.path.join(current_dir, folder_name))
                        client_socket.sendall(b"SC,Folder has been created\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,Could not create folder\n")
                        
                elif prompt_command.startswith("cd "):
                    folder_name = prompt_command[3:].strip()
                    new_dir = os.path.abspath(os.path.join(current_dir, folder_name))
                    
                    if os.path.isdir(new_dir):
                        current_dir = new_dir
                        client_socket.sendall(b"SC,Current folder has been changed\n")
                    else:
                        client_socket.sendall(b"EE,1,Folder was not found\n")
                        
                elif prompt_command.startswith("rmdir "):
                    folder_name = prompt_command[6:].strip()
                    
                    try:
                        os.rmdir(os.path.join(current_dir, folder_name))
                        client_socket.sendall(b"SC,Folder has been removed\n")
                    except FileNotFoundError:
                        client_socket.sendall(b"EE,1,Folder was not found\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,Folder could not be removed\n")
                        
                elif prompt_command.startswith("del "):
                    file_name = prompt_command[4:].strip()
                    
                    try:
                        os.remove(os.path.join(current_dir, file_name))
                        client_socket.sendall(b"SC,File has been deleted\n")
                    except FileNotFoundError:
                        client_socket.sendall(b"EE,1,File was not found\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,File could not be deleted\n")
                        
                elif prompt_command.startswith("ren "):
                    names = prompt_command.split()
                    
                    if len(names) != 3:
                        client_socket.sendall(b"EE,2,Use ren old_name new_name\n")
                    else:
                        old_folder = os.path.join(current_dir, names[1])
                        new_folder = os.path.join(current_dir, names[2])
                        
                        if not os.path.isdir(old_folder):
                            client_socket.sendall(b"EE,1,Folder was not found\n")
                        elif os.path.exists(new_folder):
                            client_socket.sendall(b"EE,3,New folder name already exists\n")
                        else:
                            try:
                                os.rename(old_folder, new_folder)
                                client_socket.sendall(b"SC,Folder has been renamed\n")
                            except OSError:
                                client_socket.sendall(b"EE,3,Folder could not be renamed\n")
                                
                elif prompt_command.startswith("dir "):
                    folder_name = prompt_command[4:].strip()

                    try:
                        folder_path = os.path.join(current_dir, folder_name)
                        file_names = "\n".join(sorted(os.listdir(folder_path)))
                        encoded_names = base64.b64encode(file_names.encode("utf-8")).decode("ascii")

                        client_socket.sendall(("DP," + encoded_names + "\n").encode("utf-8"))
                        client_socket.sendall(b"SC,Directory listed\n")
                    except (FileNotFoundError, NotADirectoryError):
                        client_socket.sendall(b"EE,1,Folder was not found\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,Folder could not be listed\n")
                        
                elif prompt_command.startswith("copy "):
                    names = prompt_command.split()

                    if len(names) != 3:
                        client_socket.sendall(b"EE,2,Use copy source destination\n")
                    else:
                        source = os.path.join(current_dir, names[1])
                        destination = os.path.join(current_dir, names[2])

                        if not os.path.isfile(source):
                            client_socket.sendall(b"EE,1,Source file was not found\n")
                        elif os.path.exists(destination):
                            client_socket.sendall(b"EE,3,Destination already exists\n")
                        else:
                            try:
                                with open(source, "rb") as original:
                                    file_data = original.read()
                                with open(destination, "xb") as copied_file:
                                    copied_file.write(file_data)
                                client_socket.sendall(b"SC,File has been copied\n")
                            except OSError:
                                client_socket.sendall(b"EE,3,File could not be copied\n")
                                
                elif prompt_command.startswith("move "):
                    names = prompt_command.split()

                    if len(names) != 3:
                        client_socket.sendall(b"EE,2,Use move source destination\n")
                    else:
                        source = os.path.join(current_dir, names[1])
                        destination = os.path.join(current_dir, names[2])

                        if not os.path.isfile(source):
                            client_socket.sendall(b"EE,1,Source file was not found\n")
                        elif os.path.exists(destination):
                            client_socket.sendall(b"EE,3,Destination already exists\n")
                        else:
                            try:
                                os.rename(source, destination)
                                client_socket.sendall(b"SC,File has been moved\n")
                            except OSError:
                                client_socket.sendall(b"EE,3,File could not be moved\n")
                                
                elif prompt_command.startswith("echo "):
                    message_text = prompt_command[5:]
                    client_socket.sendall(("SC," + message_text + "\n").encode("utf-8"))
                    
                elif prompt_command == "hostname -f":
                    computer_name = socket.getfqdn()
                    client_socket.sendall(("SC," + computer_name + "\n").encode("utf-8"))
                else:
                    client_socket.sendall(b"EE,2,Unknown prompt command\n")
            else:
                client_socket.sendall("EE,2,Unknown packet\n".encode("utf-8"))
                
    elif fields == ["SS", "RFMP", "v1.0", "1"]: #if the client chooses a secure connection
    
        # generate the rsa key pair
        public_rsa, private_rsa = create_rsa_keys() # unpacking the tuple and separating the two keys as two different variables
        server_pbkey = public_rsa.save_pkcs1() #---> turns the public_rsa OBJECT as bytes so it can be sent over the socket
        encoded_sv_pbkey = base64.b64encode(server_pbkey).decode("ascii") #---> turns ^^ into safe bytes, i.e. no \n or , and then turns the whole thing into a string for the packet
        
        # send the public rsa key to the client, .encode() bc of .sendall()
        client_socket.sendall(("CC," + encoded_sv_pbkey + "\n").encode("utf-8"))
        print("Secured connection confirmed")
        # receive the encrypted session key from the client
        encryption_packet = client_reader.readline()

        if encryption_packet == "":
            return

        encryption_packet = encryption_packet.strip()

        # decode the encrypted session key from Base64
        encrypted_session_key = base64.b64decode(encryption_packet)

        # decrypt the session key using the server's private RSA key
        session_key = decrypt_rsa(encrypted_session_key, private_rsa)

        print("Session key received and decrypted")
        # Setting the client's starting folder
        current_dir = os.path.dirname(os.path.abspath(__file__))
        print("Starting folder:", current_dir)
        
        # Keeping client connected until "End"
        for next_packet in client_reader:
            next_packet = next_packet.strip()

            if next_packet == "End":
                print("Client has ended the session")
                break

            if next_packet.startswith("CM,openRead,"):
                file_name = next_packet.split(",", 2)[2]
                print("File requested:", file_name)

                try:
                    with open(os.path.join(current_dir, file_name), "rb") as file:
                        file_content = file.read()

                    # encrypt the file using AES and the session key
                    encrypted_file = encrypt_aes(file_content, session_key)

                    # Base64 encode the encrypted file for the RFMP packet
                    encoded_file_content = base64.b64encode(encrypted_file).decode("ascii")

                    client_socket.sendall(("DP," + encoded_file_content + "\n").encode("utf-8"))
                    client_socket.sendall(b"SC,Read complete\n")

                except FileNotFoundError:
                    client_socket.sendall(b"EE,1,File not found\n")

                except OSError:
                    client_socket.sendall(b"EE,3,File could not be read\n")

            elif next_packet.startswith("CM,openWrite,"):
                file_name = next_packet.split(",", 2)[2]
                print("The file to write:", file_name)

                data_packet = client_reader.readline()

                if data_packet == "":
                    return

                data_packet = data_packet.strip()

                if data_packet == "End":
                    print("Client has ended the session")
                    return

                if not data_packet.startswith("DP,"):
                    client_socket.sendall(b"EE,2,Expected data packet\n")
                    continue

                try:
                    # Base64 decode the encrypted file
                    encrypted_file = base64.b64decode(data_packet[3:], validate=True)

                    # decrypt the file using AES and the session key
                    file_content = decrypt_aes(encrypted_file, session_key)

                    with open(os.path.join(current_dir, file_name), "wb") as output_file:
                        output_file.write(file_content)

                except (binascii.Error, ValueError):
                    client_socket.sendall(b"EE,2,Data packet is invalid\n")

                except OSError:
                    client_socket.sendall(b"EE,3,The file could not be written\n")

                else:
                    client_socket.sendall(b"SC,Write is complete\n")
                
            elif next_packet.startswith("CM,prompt,"):
                prompt_command = next_packet.split(",", 2)[2]
                
                if prompt_command.startswith("mkdir "):
                    folder_name = prompt_command[6:].strip()
                    
                    try:
                        os.mkdir(os.path.join(current_dir, folder_name))
                        client_socket.sendall(b"SC,Folder has been created\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,Could not create folder\n")
                        
                elif prompt_command.startswith("cd "):
                    folder_name = prompt_command[3:].strip()
                    new_dir = os.path.abspath(os.path.join(current_dir, folder_name))
                    
                    if os.path.isdir(new_dir):
                        current_dir = new_dir
                        client_socket.sendall(b"SC,Current folder has been changed\n")
                    else:
                        client_socket.sendall(b"EE,1,Folder was not found\n")
                        
                elif prompt_command.startswith("rmdir "):
                    folder_name = prompt_command[6:].strip()
                    
                    try:
                        os.rmdir(os.path.join(current_dir, folder_name))
                        client_socket.sendall(b"SC,Folder has been removed\n")
                    except FileNotFoundError:
                        client_socket.sendall(b"EE,1,Folder was not found\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,Folder could not be removed\n")
                        
                elif prompt_command.startswith("del "):
                    file_name = prompt_command[4:].strip()
                    
                    try:
                        os.remove(os.path.join(current_dir, file_name))
                        client_socket.sendall(b"SC,File has been deleted\n")
                    except FileNotFoundError:
                        client_socket.sendall(b"EE,1,File was not found\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,File could not be deleted\n")
                        
                elif prompt_command.startswith("ren "):
                    names = prompt_command.split()
                    
                    if len(names) != 3:
                        client_socket.sendall(b"EE,2,Use ren old_name new_name\n")
                    else:
                        old_folder = os.path.join(current_dir, names[1])
                        new_folder = os.path.join(current_dir, names[2])
                        
                        if not os.path.isdir(old_folder):
                            client_socket.sendall(b"EE,1,Folder was not found\n")
                        elif os.path.exists(new_folder):
                            client_socket.sendall(b"EE,3,New folder name already exists\n")
                        else:
                            try:
                                os.rename(old_folder, new_folder)
                                client_socket.sendall(b"SC,Folder has been renamed\n")
                            except OSError:
                                client_socket.sendall(b"EE,3,Folder could not be renamed\n")
                                
                elif prompt_command.startswith("dir "):
                    folder_name = prompt_command[4:].strip()

                    try:
                        folder_path = os.path.join(current_dir, folder_name)
                        file_names = "\n".join(sorted(os.listdir(folder_path)))
                        encoded_names = base64.b64encode(file_names.encode("utf-8")).decode("ascii")

                        client_socket.sendall(("DP," + encoded_names + "\n").encode("utf-8"))
                        client_socket.sendall(b"SC,Directory listed\n")
                    except (FileNotFoundError, NotADirectoryError):
                        client_socket.sendall(b"EE,1,Folder was not found\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,Folder could not be listed\n")
                        
                elif prompt_command.startswith("copy "):
                    names = prompt_command.split()

                    if len(names) != 3:
                        client_socket.sendall(b"EE,2,Use copy source destination\n")
                    else:
                        source = os.path.join(current_dir, names[1])
                        destination = os.path.join(current_dir, names[2])

                        if not os.path.isfile(source):
                            client_socket.sendall(b"EE,1,Source file was not found\n")
                        elif os.path.exists(destination):
                            client_socket.sendall(b"EE,3,Destination already exists\n")
                        else:
                            try:
                                with open(source, "rb") as original:
                                    file_data = original.read()
                                with open(destination, "xb") as copied_file:
                                    copied_file.write(file_data)
                                client_socket.sendall(b"SC,File has been copied\n")
                            except OSError:
                                client_socket.sendall(b"EE,3,File could not be copied\n")
                                
                elif prompt_command.startswith("move "):
                    names = prompt_command.split()

                    if len(names) != 3:
                        client_socket.sendall(b"EE,2,Use move source destination\n")
                    else:
                        source = os.path.join(current_dir, names[1])
                        destination = os.path.join(current_dir, names[2])

                        if not os.path.isfile(source):
                            client_socket.sendall(b"EE,1,Source file was not found\n")
                        elif os.path.exists(destination):
                            client_socket.sendall(b"EE,3,Destination already exists\n")
                        else:
                            try:
                                os.rename(source, destination)
                                client_socket.sendall(b"SC,File has been moved\n")
                            except OSError:
                                client_socket.sendall(b"EE,3,File could not be moved\n")
                                
                elif prompt_command.startswith("echo "):
                    message_text = prompt_command[5:]
                    client_socket.sendall(("SC," + message_text + "\n").encode("utf-8"))
                    
                elif prompt_command == "hostname -f":
                    computer_name = socket.getfqdn()
                    client_socket.sendall(("SC," + computer_name + "\n").encode("utf-8"))
                else:
                    client_socket.sendall(b"EE,2,Unknown prompt command\n")
            else:
                client_socket.sendall(b"EE,2,Unknown packet\n")

    else:
        client_socket.sendall("EE,4,Invalid setup packet\n".encode("utf-8"))
        print("Invalid setup packet:", message)
        



# Managing the connection and closing it after the session
def handle_connection(client_socket, address):
    try:
        with client_socket:
            with client_socket.makefile("r", encoding="utf-8") as client_reader:
                client_handler(client_socket, address, client_reader)

    except (OSError, UnicodeError) as error:
        print("Client connection error:", address, error)

    finally:
        print("Client has been disconnected:", address)
while True:
    client_socket, address = server_socket.accept()

    threading.Thread(
        target=handle_connection,
        args=(client_socket, address),
        daemon=True
    ).start()