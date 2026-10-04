import socket # Provides TCP networking functions for connecting to the RFMP server
import base64 # Encodes/decodes binary data so it can be safely sent in text packets
import rsa # Provides RSA key handling for the secure connection mode

from security_funcs import ( # Imports encryption helper functions
    create_rsa_keys, # Generate the client's RSA public/private key pair
    create_session_key, # Generates 16 byte session key
    encrypt_rsa, # Encrypts the session key using the server's RSA public key
    encrypt_aes, # Encrypts data using AES (works mainly with bytes)
    decrypt_aes, # Decrypts data using AES
    encrypt_caesar, # Encrypts data using Caesar cipher (works mainly with strings)
    decrypt_caesar # Decrypts data using Caesar cipher
)
# Sends 1 complete RFMP packet followed by a newline
def send_packet(sock, packet): # receives socket and packet text
    sock.sendall((packet + "\n").encode("utf-8")) # adds newline, converts to bytes and sends to server

# Receives one complete RFMP packet from the server 
def receieve_packet(reader): # receives text reader connected to the socket
    return reader.readline().strip() # reads one packet and removes the ending newline

# Requests a file from the RFMP server & displays its contents
def open_read(sock,reader): # function for requesting & receiving a file from the server
    # Ask the user which server file they want to read
    file_name = input("Enter the name of the file to read from the server: ")
    
    # Create the RFMP openRead command packet
    read_packet = "CM,openRead," + file_name
    
    # Send the openRead request to the server
    send_packet(sock, read_packet)
    
    # Show the command that was sent 
    print("Sent:", read_packet)
    
    # Receive the server's first response
    response = receieve_packet(reader)
    
    # Check if the server returned file data 
    if response.startswith("DP,"): # checks packet type, DP = Data Packet
        # Remove the DP, packet header
        encoded_content = response[3:] # takes the string after the first 3 characters (DP,)
        
        # Decode Base64 data from the Data Packet
        received_data = base64.b64decode(encoded_content) # base64 decoding converts the data back to original bytes
        
        # Decrypt the file if secured AES mode is active
        if secure_mode and algorithm == "AES": # runs only if secure mode is active and AES is the selected algorithm
            file_content = decrypt_aes( # client takes received encrypted bytes and decrypts them using the shared session key
                received_data,
                session_key # server uses key to encrypt, client uses key to decrypt
            ).decode("utf-8") # turns decrypted bytes into readable text using UTF-8 encoding
        
        elif secure_mode and algorithm == "Caesar": # runs only if secure mode is active and Caesar is the selected algorithm
            encrypted_text = received_data.decode("latin-1") # received bytes are first converted into text using latin-1 since Caesar cipher works on text, then the caesar cipher reverses letter shifts to get the original text
            # caesar works on text, not raw bytes, latin-1 conrverts received bytes into characters safely
            file_content = decrypt_caesar( # shifts letter back to original position using the caesar shift value
                encrypted_text,
                caesar_shift # tells how far the letters were shifted
            )
        
        else: # if encryption is not enabled, there is nothing to decrypt, client simply converts the file bytes into readable text and prints them
            # Unsecured mode contains normal file bytes
            file_content = received_data.decode("utf-8") # converts the received bytes into readable text using UTF-8 encoding
        
        # Display the file contents to the user
        print("\nFile contents received from server:") # displays a header for the file contents
        print(file_content) # displays the actual file contents received from the server
        
        # Unsecured mode: Base64 decode -> UTF-8 readable text
        # AES mode: Base64 decode -> AES decrypt -> UTF-8 readable text
        # Caesar mode: Base64 decode -> Latin-1 -> Caesar decrypt -> UTF-8 readable text
            
    
        # Receive the final success packet
        status = receieve_packet(reader) # after file data arrives, client waits for one more packet, usually the server sends a success packet to confirm that the file was sent successfully
        # RFMP sends file data first, then a separate success packet confirming the command completed
        
        # Display the server status
        print("Server status:", status)
    
    # Check if server returned an error packet
    elif response.startswith("EE,"): # if the server could not read the file, it sends an error packet instead of data packet
        # Display the error message from the server
        print("Error received from server:", response) # print the error received from the server
    
    # Catch any unexpected responses from the server
    else: # if the response is neither DP, .. . nor EE, then it is unexpected and the client will print it out for debugging purposes
        # safely handle any response that does not match the expected RFMP packet types
        print("Unexpected response from server:", response) 

# Sends file data to the RFMP server so it can be written to a file
def open_write(sock, reader): # function handles writing a file onto the server, it asks for the filename then the text that should be written into the file, then it sends the data to the server
    # open_write sends filename and file contents to the server so the server can create/overwrite that file
    # Ask the user for the name of the file to create/overwrite on the server 
    file_name = input("Enter the name of the file to create/overwrite on the server: ")
    
    # Ask the user for the text that should be written into the file
    file_content = input("Enter the text to write into the file: ")
    
    # Create the RFMP openWrite command packet
    write_packet = "CM,openWrite," + file_name 
    
    # Send the openWrite command to the server
    send_packet(sock, write_packet) # client sends this first so the server knows which file it is about to receive data for
    
    # Show that the command was sent
    print("Sent:", write_packet)
    
    # Convert file contents into bytes
    file_bytes = file_content.encode("utf-8") 
    
    # Encrypt file contents when secured AES mode is active
    if secure_mode and algorithm == "AES":
        data_to_send = encrypt_aes( # if AES was selected, those bytes are encrypted using the shared session key before being sent to the server
            file_bytes,
            session_key
        )
    
    # Encrypt file contents when secured Caesar mode is active
    elif secure_mode and algorithm == "Caesar":
        encrypted_text = encrypt_caesar(
            file_content, # the original text is encrypted using the caesar cipher, which shifts letters by a certain number of positions
            caesar_shift # tells how far the letters should be shifted
        )
        
        data_to_send = encrypted_text.encode("latin-1") # the encrypted text is then converted into bytes using latin-1 encoding so it can be sent to the server
    
    # if secured mode is not enabled, the client simply sends the original file contents as bytes without any encryption (the original utf-8 encoded bytes are sent to the server)
    else:
        # Unsecured mode sends the original file contents 
        data_to_send = file_bytes
        # in unsecured mode, the file contents are sent without encryption, although they are still Base64-encoded to ensure safe transmission in text packets
    
    # Base64 encodes the data for RFMP Data packet 
    encoded_content = base64.b64encode( # Base64 conerts those bytes into a safe text after encryption format that can be sent in the RFMP Data Packet, this is done regardless of whether the data was encrypted or not
        data_to_send
    ).decode("ascii") # converts the Base64 bytes into normal text
    
    # Create RFMP Data Packet
    data_packet = "DP," + encoded_content # client adds the DP, header to the Base64-encoded data so the server knows it is receiving a Data Packet
    
    # Send Data Packet to the server
    send_packet(sock, data_packet) # so the first packet tells the server which file to write to, and the second packet contains the actual data to write into that file
    # second packet contains the actual file data, which may be encrypted or not depending on the connection mode
    
    # Confirm that the file data was sent 
    print("Sent file data to server.")
    
    # Receive the server's final response
    response = receieve_packet(reader)
    
    # Check whether the server successfully wrote the file data
    if response.startswith("SC,"): # if the server successfully wrote the file data, it sends a success packet back to the client
        print("Server status:", response)
        # client only sends filename and data, the server handles writing the file and then sends a success packet back to the client to confirm that the file was written successfully
    
    # Check whether the server returned an error packet
    elif response.startswith("EE,"):
        print("Error received from server:", response)
    # if the server could not write the file, it sends an error packet back to the client, which is then printed out for debugging purposes
    # for example: invaid filename, invalid packet
        
    # Catch any unexpected responses from the server
    else:
        print("Unexpected response from server:", response)

def prompt_command(sock,reader): # this function lets the user send system/file-management commands to the server
        # Show the required and additional supported system commands
        print("\nAvailable prompt commands:")
        print("Required: mkdir, cd, rmdir/rd, del, ren")
        print("Additional: dir, copy, move, echo, hostname -f")
            
        # Ask the user to enter the complete command 
        command = input("Enter the full system command to send to the server: ").strip() # client asks the user for the full command and removes unwanted spaces
        
        # Prevent an empty command from being sent to the server
        if command == "":
                print("Command cannot be empty.")
                return # if nothing was entered, the function returns to the main menu without sending anything to the server
            
        # Create the RFMP prompt command packet
        prompt_packet = "CM,prompt," + command # converts the user's command into a RFMP packet with the CM, header so the server knows it is a command packet
            
        # Send the prompt command to the server
        send_packet(sock, prompt_packet) # this sends the command to the server so it can be executed on the server's system
            
        #Show the packet that was sent
        print("Sent:", prompt_packet) # client prints the command for the user, then waits for the server's response
        
        # Receive the server's response to the prompt command
        response = receieve_packet(reader)
        
        # Check whether the server returned a Data Packet
        if response.startswith("DP,"): # if the response starts with DP, then the server is sending back data, so the client will decode and decrypt it if necessary, then print it out for the user
            encoded_data = response[3:] # removes the DP header from the response so that only the Base64-encoded data remains
            received_data = base64.b64decode(encoded_data) # converts safe text back into bytes because the server encoded the data into Base64 before sending it to the client
            
            # Decrypt directory listing when secured AES mode is active
            if secure_mode and algorithm == "AES": # if the connection is secure and AES was chosen, the client decrypts the bytes using the shared session key
                directory_listing = decrypt_aes( # decrypt the bites
                    received_data, # the Base64-decoded bytes
                    session_key
                ).decode("utf-8") # convert the decrypted bytes into readable text
            # Base64 only restores the encrypted bytes, AES decryption is what restores the original text
            
            # Decrypt directory listing when secured Caesar mode is active
            elif secure_mode and algorithm == "Caesar": # if Caesar was selected, the bytes are first converted to text with latin-1, then Caesar shift is reversed
                encrypted_text = received_data.decode("latin-1") # convert bytes to text with latin-1
                # caesar helper expects a string, so bytes must first be converted into text
                
                directory_listing = decrypt_caesar(
                    encrypted_text,
                    caesar_shift # reverse the caesar shift
                ) 
            
            # Unsecured directory listing contains normal bytes
            else: # if connection is unsecured, no decryption is needed
                directory_listing = received_data.decode("utf-8") # bytes are simply converted into normal text and displayed
            
            print("\nDirectory listing received from server:") 
            print(directory_listing) # final directory contents printed for the user
            # in unsecured mode, the client only Base64-decodes and UTF-8 decodes the data, so no decryption step
            
            # Receive the final success packet from the server
            status = receieve_packet(reader)
            print("Server status:", status) # after sending the directory listing, the server sends a second packet confirming success
               
        # Check whether the server successfully executed the command
        elif response.startswith("SC,"): # confirms the command was successful (mkdir may return only this)
                print("Server status:", response)
                
        # Check whether server returned error 
        elif response.startswith("EE,"): # confirms the command failed (mkdir may return only this)
                print("Error received from server:", response)
        
        else: # catches any response that is not DP, SC, or EE
                print("Unexpected response from server:", response) # prevents unknown packets from being treated as valid
# command prompt expects DP for returned data, SC for success and EE for errors

HOST = "127.0.0.1" # Server address used for same machine testing (local host)
PORT = 8888 # Must match the server port, client and server must use same port, if port numbers are different, client will not connect to server

# Create an IPv4 TCP Client socket 
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # AF_INET is IPv4, SOCK_STREAM is TCP which is reliable

# Connect the socket to RFMP server 
client_socket.connect((HOST, PORT)) # connect() starts the TCP connection

# Confirms that the TCP connection is established
print("Connected to RFMP server.")

# Ask the user whether the RFMP connection should be secured
print("\nConnection mode:")
print("0. Unsecured") # no encryption
print("1. Secured") # encryption mode, encryption is added at the application level

security_choice = input("Choose connection mode (0 or 1): ").strip()

while security_choice not in ("0", "1"): # prevents invalid setup values, keeps asking user until valid choice entered
    print("Invalid choice. Enter 0 for unsecured or 1 for secured.")
    security_choice = input("Choose connection mode (0 or 1): ").strip()

secure_mode = security_choice == "1" # secure_mode is a boolean and is true if user chose 1 and false if user chose 0

# Values used later when secure file transfer is enabled
# these variables are created before setup so they exist whether the connection is secure or not, start them as None because values are only created later if secure mode selected
algorithm = None # AES / Caesar
session_key = None # the shared key
caesar_shift = None # shift amount for Caesar

# Create and send the RFMP Start packet
start_packet = "SS,RFMP,v1.0," + security_choice # SS is start/setup packet, final value is secured/unsecured
send_packet(client_socket, start_packet)

print("Sent Start packet:", start_packet)

# Create a text reader so responses can be read one line at a time
client_reader = client_socket.makefile("r", encoding="utf-8") # socket is wrapped as a text reader so the client can use readline

# Receive the server's Confirm-Connection packet
response = receieve_packet(client_reader)

print("Received from server:", response)

connection_ready = False # the client first assumes setup has not succeeded

# Unsecured connection
if not secure_mode and response == "CC": # if unsecured mode was selected and the server replies exactly CC, the connection marked ready
    print("Unsecured RFMP connection established successfully.")
    connection_ready = True # controls whether menu can start, becomes true only after valid setup

# Secured connection
elif secure_mode and response.startswith("CC,"): # runs when secure mode was true, and server replies with CC, public key
    # Extract the server's Base64-encoded RSA public key
    encoded_server_key = response.split(",", 1)[1] #client removes CC 

    # Convert the server public key back into an RSA key object
    server_key_bytes = base64.b64decode(encoded_server_key) # Base64 decodes the key - safe text -> bytes
    server_public_key = rsa.PublicKey.load_pkcs1(server_key_bytes) # after decoding the key, it is turned into an RSA public-key object it can actually use
    # load_pkcs1() rebuilds the RSA public-key object, server sends its public key so client can use it to encrypt session key
    print("Server RSA public key received successfully.")

    # Ask which encryption algorithm should be used
    print("\nEncryption algorithm:")
    print("1. AES")
    print("2. Caesar")

    algorithm_choice = input(
        "Choose encryption algorithm (1 or 2): "
    ).strip()

    while algorithm_choice not in ("1", "2"): # invalid input rejected in a loop
        print("Invalid choice. Enter 1 for AES or 2 for Caesar.")
        algorithm_choice = input(
            "Choose encryption algorithm (1 or 2): "
        ).strip()

    algorithm = "AES" if algorithm_choice == "1" else "Caesar" # AES is choice 1

    # Generate the client's RSA public/private key pair 
    client_public_key, client_private_key = create_rsa_keys() # client creates its own RSA key pair then creates the random session key that will be used during the secure connection

    # Generate the required 16-byte session key
    session_key = create_session_key() # create temporary session key used for AES

    # Encrypt the session key using the server's RSA public key
    encrypted_session_key = encrypt_rsa( # client encrypts the session key using the server's public key
        session_key,
        server_public_key
    )

    # Convert encrypted session key to Base64
    encoded_session_key = base64.b64encode( # then it Base64 encodes the encrypted bites so they can safely go inside the RFMP packet
        encrypted_session_key
    ).decode("ascii")
    
    # Original session key is not sent directly, server public key encrypts it, server private key later decrypts it
    # Base64 is only for safe packet transport
    # RSA protects the session key while it is being sent

    # Convert client public RSA key to PEM and then Base64
    client_public_key_bytes = client_public_key.save_pkcs1() # save_pkcs1() serialises the RSA public key into bytes

    encoded_client_key = base64.b64encode( # client's public RSA key is converted into bytes, and then BASE64 text so it can also be placed inside encryption packet                                    
        client_public_key_bytes 
    ).decode("ascii")

    username = input("Enter username: ").strip()

    while username == "": # keep asking for username if it is empty
        print("Username cannot be empty.")
        username = input("Enter username: ").strip()

    # Create the RFMP Encryption Packet
    encryption_packet = ( # combine all secure-setup information into one RFMP encryption packet
        "EC,"
        + algorithm
        + ","
        + encoded_session_key
        + ","
        + username
        + ":"
        + encoded_client_key
    )

    # Send EC packet. The server sends no acknowledgement after EC.
    send_packet(client_socket, encryption_packet) # EC is sent only in secure mode

    # Calculate Caesar shift now in case Caesar was selected
    caesar_shift = session_key[0] % 25 + 1 # session_key[0] is the first byte of the session key, %25+1 makes the ceasar shift between 1 and 25

    print("Sent Encryption Packet using", algorithm)
    print("Secured RFMP connection established successfully.")

    connection_ready = True # allows normal menu to start

# Run the normal RFMP menu only after setup succeeds
if connection_ready: # this menu only starts if the setup phase succeeded so the client cannot start sending commands if the setup failed
    
    # Keep showing the menu until the user chooses to end the session 
    while True:
        # Show the menu of available RFMP commands
        print("\nRFMP Client Menu:")
        print("1. Prompt Command - Run a system command on the server")
        print("2. Open Read - Read a file from the server")
        print("3. Open Write - Write a file to the server")
        print("4. Exit - End the client session") 
        
        # Ask the user to select a menu option
        choice = input("Enter your choice (1, 2, 3, or 4): ")
        
        # Run a system command on the server, socket and reader passed into functions as functions need socket to send and reader to receive 
        if choice == "1":
            prompt_command(client_socket, client_reader) # if 1 is selected, it calls prompt_command()
        
        # Read a file from the server
        elif choice == "2":
            open_read(client_socket, client_reader) # server -> client file transfer
        
        # Write a file to the server
        elif choice == "3":
            open_write(client_socket, client_reader) # client -> server file transfer
            
        # End the RFMP server session and close the client
        # if the user chooses Exit, the client sends the RFMP closing packet End, then break stops the menu loop
        elif choice == "4":
            end_packet = "End" # the RFMP closing phase packet
            send_packet(client_socket, end_packet)
            print("Sent close session packet:", end_packet)
            break
        
        else: # handles invalid menu choices
            print("Invalid choice. Please select a valid option.")  
            
else: # belongs to if connection_ready and runs if the setup never succeeded
    print("Failed to establish RFMP connection:", response)

# After menu ends, client closes text reader and closes the TCP socket
# Close the reader
client_reader.close()

# Close the client socket to terminate the TCP connection
client_socket.close()

# Confirm that client session has ended
print("Connection to RFMP server closed. Client session ended.")