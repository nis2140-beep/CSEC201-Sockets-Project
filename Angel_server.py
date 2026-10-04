import socket
import base64
import binascii
import os
import threading
import rsa

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.decrepit.ciphers import modes

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
        if "A" <= char <= "Z" or "a" <= char <= "z": #checks if char is a letter (true), false if spaces or numbers or punctuation
            
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
host = "127.0.0.1" # localhost, server and client are running on the same computer
port = 8888 # port used for the RFMP connection

# AF_INET uses IPv4 + SOCK_STREAM creates a TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# This connects the server socket to the chosen IP address + port
server_socket.bind((host,port))

# This puts the socket into listening mode so it can accept client connections
server_socket.listen(5) # 5 is max number of queued connections, but the OS may allow more

print("RFMP server is listening on port", port)

# Client handler + setup packet section
# Here, server handles new client connection and decides if the session will be unsecured (0) or secured (1) based on the setup packet sent by the client

def client_handler(client_socket, address, client_reader):
    # Handles communication with one connected client
    print("Client is connected:", address)

    # Reads client's start packet in setup phase
    message = client_reader.readline()
    
    # An empty string means client disconnected before sending packet
    if message == "":
        return
    
    # This removes newline (\n) + separates packet fields by commas
    message = message.strip()
    print("Client sent: ", message)
    fields = message.split(",")
    
    # The 0 means client requested an unsecured connection
    # SS - Setup/start packet (first message sent by client to server + tells server this is start message)
    # RFMP - protocol (tells it which protocol youre using)
    # v1.0 - version
    # If fields match the expected values, the server sends back a confirmation packet (CC) to the client
    if fields == ["SS", "RFMP", "v1.0", "0"]:
        # .encode("utf-8") coverts Python string to bytes because socket sends bytes
        # sendall() attempts to send entire byte sequence instead of you manually handling partial sends
        client_socket.sendall("CC\n".encode("utf-8"))
        print("Unsecured connection confirmed")
        
        # Setting the client's starting folder to folder where server file is located
        # __file__ = path/name of Python server file currently running
        # os.path.abspath(__file__) = gets its absolute/full path
        # os.path.dirname(...) = gets the folder where the server file is located
        current_dir = os.path.dirname(os.path.abspath(__file__))
        print("Starting folder:", current_dir)
        
        
        # Keeps reading packets from client until session ends
        for next_packet in client_reader:
            # Removes \n from each received packet
            next_packet = next_packet.strip()
            
            # Stops loop if client sends End
            if next_packet == "End":
                print("Client has ended the session")
                break # exit this for loop, doesn't exit the whole function, just the for loop
                
            # Checks if client sends an openRead command
            if next_packet.startswith("CM,openRead,"):
                # Gets requested filename from command packet (CM)
                file_name = next_packet.split(",",2)[2]
                print("File requested:", file_name)
                
                try:
                    # Opens requested file in binary read mode, reads its content, and closes the file automatically after leaving the with block
                    # os.path.join() combines current server-side directory with requested filename
                    # rb -> r = read, b = binary
                    # This is done to ensure that the file is read in binary mode, which is important for handling non-text files correctly.
                    
                    with open(os.path.join(current_dir, file_name), "rb") as file:
                        # Reads the file contents into file_content
                        file_content = file.read()
                        
                    # This converts file data into Base64 for sending in the packet
                    # b64encode -> converts raw file bytes into Base64 bytes
                    # .decode("ascii") converts the Base64 bytes into a Python string so it can be combined with "DP,"
                    # Base64 is ENCODING, not ENCRYPTION. It is used to safely transmit binary data over text-based protocols.
                    encoded_file_content = base64.b64encode(file_content).decode("ascii")
                    
                    # This sends the file data to the client
                    # Sends packet over TCP connection, adds newline (\n) to indicate end of packet, and encodes the string into bytes for transmission
                    client_socket.sendall(("DP," + encoded_file_content + "\n").encode("utf-8"))
                    
                    # This sends a success confirmation packet to the client
                    client_socket.sendall(b"SC,Read complete\n")

                # This sends an error if requested file does not exist
                except FileNotFoundError:
                    client_socket.sendall(b"EE,1,File not found\n") # 1 = couldnt find the file
                # This sends an error if the file cannot be read for any other reason
                except OSError:
                    client_socket.sendall(b"EE,3,File could not be read\n") # 3 = couldnt read the file for some reason
                    
            # Checks if client sent an openWrite command
            elif next_packet.startswith("CM,openWrite,"):
                
                # Gets the filename that the client wants to write to
                file_name = next_packet.split(",", 2)[2]
                print("The file to write:", file_name)
                
                # Reads the next packet from the client, which should contain the file data
                # First packet tells the server what to do + which file, second carries what to put inside file
                data_packet = client_reader.readline()
                
                # Empty string = client disconnected
                if data_packet == "":
                    return 

                data_packet = data_packet.strip()
                
                # Ends the session if the client sends "End" instead of a data packet
                if data_packet == "End":
                    print("Client has ended the session")
                    return
                
                # openWrite expects the next packet to be a data packet (DP)
                if not data_packet.startswith("DP,"):
                    client_socket.sendall(b"EE,2,Expected data packet\n")
                    continue # continues to the next iteration of the for loop, waiting for the next packet from the client
                
                try:
                    # This removes DP, decodes Base64 data back into original file bytes
                    # the [3:] removes the DP prefix from the packet, leaving only the Base64-encoded data
                    # validate=True ensures that the Base64 data is valid and raises an error if it is not
                    file_content = base64.b64decode(data_packet[3:], validate=True)
                    
                    # This opens requested file in binary write mode + writes data
                    with open(os.path.join(current_dir, file_name), "wb") as output_file:
                        output_file.write(file_content) # saves the file content to the file, overwriting if it already exists
                        
                # Handles invalid Base64 data
                except (binascii.Error, ValueError):
                    client_socket.sendall(b"EE,2,Data packet is invalid\n")
                # Handles errors that stop file from being written
                except OSError:
                    client_socket.sendall(b"EE,3,The file could not be written\n")
                # Only sends success if no exception has happened
                else:
                    client_socket.sendall(b"SC,Write is complete\n")
                    
            # Checks if client sent a prompt command (CM,prompt)
            elif next_packet.startswith("CM,prompt,"):
                
                # This extracts the actual command from packet
                prompt_command = next_packet.split(",", 2)[2]
                
                # This handles mkdir command + gets new folder name from the command
                if prompt_command.startswith("mkdir "):
                    folder_name = prompt_command[6:].strip()
                    
                    try:
                        # This creates the folder inside client's current directory 
                        os.mkdir(os.path.join(current_dir, folder_name))
                        client_socket.sendall(b"SC,Folder has been created\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,Could not create folder\n")
                        
                # This creates new path + checks that folder exists before changing current_dir
                elif prompt_command.startswith("cd "):
                    folder_name = prompt_command[3:].strip()
                    new_dir = os.path.abspath(os.path.join(current_dir, folder_name))
                    
                    # This checks if the new directory exists and is a directory, then changes current_dir to new_dir
                    if os.path.isdir(new_dir):
                        current_dir = new_dir
                        client_socket.sendall(b"SC,Current folder has been changed\n")
                    else:
                        client_socket.sendall(b"EE,1,Folder was not found\n")
                        
                # This removes a folder from the current directory, checks if it exists first, and handles errors
                elif prompt_command.startswith("rmdir "):
                    folder_name = prompt_command[6:].strip() # Gets the folder name from the command
                    
                    try:
                        # This attempts to remove the folder from the current directory
                        os.rmdir(os.path.join(current_dir, folder_name))
                        client_socket.sendall(b"SC,Folder has been removed\n")
                    except FileNotFoundError:
                        client_socket.sendall(b"EE,1,Folder was not found\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,Folder could not be removed\n")
                
                # This removes a file from the current directory, checks if it exists first, and handles errors
                elif prompt_command.startswith("del "):
                    file_name = prompt_command[4:].strip()
                    
                    try:
                        os.remove(os.path.join(current_dir, file_name))
                        client_socket.sendall(b"SC,File has been deleted\n")
                    except FileNotFoundError:
                        client_socket.sendall(b"EE,1,File was not found\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,File could not be deleted\n")
                        
                # This renames a folder in the current directory, checks if it exists first, and handles errors
                elif prompt_command.startswith("ren "):
                    # This splits the command into parts to get the old and new folder names
                    names = prompt_command.split()
                    
                    # This checks if the command has the correct number of arguments (3: ren, old_name, new_name)
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
                
                # This lists the contents of a folder in the current directory, checks if it exists first, and handles errors
                elif prompt_command.startswith("dir "):
                    folder_name = prompt_command[4:].strip()

                    try:
                        folder_path = os.path.join(current_dir, folder_name) # creates the full path to the folder to be listed
                        # Gets + sorts files in requested folder, joins them into a single string with newlines between each file name
                        # os.listdir() gets folder contents
                        # sorted() sorts the list of file names alphabetically
                        file_names = "\n".join(sorted(os.listdir(folder_path)))
                        
                        # Base64 encodes the directory listing before sending it in DP packet
                        encoded_names = base64.b64encode(file_names.encode("utf-8")).decode("ascii")

                        client_socket.sendall(("DP," + encoded_names + "\n").encode("utf-8"))
                        client_socket.sendall(b"SC,Directory listed\n")
                    except (FileNotFoundError, NotADirectoryError):
                        client_socket.sendall(b"EE,1,Folder was not found\n")
                    except OSError:
                        client_socket.sendall(b"EE,3,Folder could not be listed\n")
                # This reads the source file + writes same data into new destination file
                elif prompt_command.startswith("copy "):
                    names = prompt_command.split() # splits the command into parts to get the source and destination file names

                    if len(names) != 3: 
                        client_socket.sendall(b"EE,2,Use copy source destination\n")
                    else:
                        source = os.path.join(current_dir, names[1]) # creates the full path to the source file to be copied
                        destination = os.path.join(current_dir, names[2]) # creates the full path to the destination file where the copy will be saved

                        if not os.path.isfile(source):
                            client_socket.sendall(b"EE,1,Source file was not found\n")
                        elif os.path.exists(destination):
                            client_socket.sendall(b"EE,3,Destination already exists\n")
                        else:
                            try:
                                # This opens source file in binary read mode + reads its content
                                with open(source, "rb") as original:
                                    file_data = original.read()
                                # This opens destination file in binary write mode + writes the copied data
                                with open(destination, "xb") as copied_file:
                                    copied_file.write(file_data)
                                client_socket.sendall(b"SC,File has been copied\n")
                            except OSError:
                                client_socket.sendall(b"EE,3,File could not be copied\n")
                
                # This moves source file to new destination
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
                                os.rename(source, destination) # renames the source file to the destination file, effectively moving it
                                client_socket.sendall(b"SC,File has been moved\n")
                            except OSError:
                                client_socket.sendall(b"EE,3,File could not be moved\n")
                
                # This sends the provided message back in success packet
                elif prompt_command.startswith("echo "):
                    message_text = prompt_command[5:] # extracts the text to be echoed back to the client
                    client_socket.sendall(("SC," + message_text + "\n").encode("utf-8"))
                
                # This gets the computers fully qualified hostname
                elif prompt_command == "hostname -f":
                    computer_name = socket.getfqdn()
                    client_socket.sendall(("SC," + computer_name + "\n").encode("utf-8"))
                else:
                    client_socket.sendall(b"EE,2,Unknown prompt command\n")
            else:
                client_socket.sendall("EE,2,Unknown packet\n".encode("utf-8"))
    
    # 1 means client requested secured connection
    elif fields == ["SS", "RFMP", "v1.0", "1"]:
    
        # Creates server's RSA public + private keys
        public_rsa, private_rsa = create_rsa_keys()
        
        # Converts server's public key into bytes so it can be sent to client
        server_pbkey = public_rsa.save_pkcs1()
        
        # Base64 encodes public key so it can be included in CC packet
        encoded_sv_pbkey = base64.b64encode(server_pbkey).decode("ascii")
        
        # Confirms connection + sends server's public RSA key to client
        client_socket.sendall(("CC," + encoded_sv_pbkey + "\n").encode("utf-8"))
        
        # Receiving the client's encryption packet
        encryption_packet = client_reader.readline()

        if encryption_packet == "" or encryption_packet.strip() == "End":
            return

        try:
            encryption_fields = encryption_packet.strip().split(",", 3)

            if len(encryption_fields) != 4:
                raise ValueError

            if encryption_fields[0] != "EC":
                raise ValueError

            algorithm = encryption_fields[1]
            if algorithm not in ("AES", "Caesar"):
                raise ValueError

            # Recovering the session key using the server's private key
            encrypted_session_key = base64.b64decode(
                encryption_fields[2], validate=True
            )
            session_key = decrypt_rsa(encrypted_session_key, private_rsa)

            if len(session_key) != 16:
                raise ValueError

            # Receiving the username and client's public key
            username, encoded_client_key = encryption_fields[3].split(":", 1)
            client_public_key = base64.b64decode(
                encoded_client_key, validate=True
            )

            if not username.strip() or not client_public_key:
                raise ValueError

        except (binascii.Error, ValueError, rsa.DecryptionError):
            client_socket.sendall(b"EE,4,Invalid encryption packet\n")
            return

        caesar_shift = session_key[0] % 25 + 1

        print("Secured connection confirmed:", algorithm)
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

                    # Encrypting the file using the selected algorithm
                    if algorithm == "AES":
                        encrypted_file = encrypt_aes(file_content, session_key)
                    else:
                        file_text = file_content.decode("latin-1")
                        encrypted_file = encrypt_caesar(
                            file_text, caesar_shift
                        ).encode("latin-1")

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

                    # Decrypting the file using the selected algorithm
                    if algorithm == "AES":
                        file_content = decrypt_aes(encrypted_file, session_key)
                    else:
                        encrypted_text = encrypted_file.decode("latin-1")
                        file_content = decrypt_caesar(
                            encrypted_text, caesar_shift
                        ).encode("latin-1")

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
                        # Encrypting the directory output
                        directory_data = file_names.encode("utf-8")

                        if algorithm == "AES":
                            encrypted_names = encrypt_aes(directory_data, session_key)
                        else:
                            directory_text = directory_data.decode("latin-1")
                            encrypted_names = encrypt_caesar(
                                directory_text, caesar_shift
                            ).encode("latin-1")

                        encoded_names = base64.b64encode(encrypted_names).decode("ascii")

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