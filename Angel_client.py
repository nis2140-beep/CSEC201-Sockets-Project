import socket # Provides TCP socket functions 
import base64 # Used to decode file data received from the server
import rsa

from security_funcs import (
    create_rsa_keys,
    create_session_key,
    encrypt_rsa,
    encrypt_aes,
    decrypt_aes,
    encrypt_caesar,
    decrypt_caesar
)
# Sends 1 RFMP packet followed by a newline
def send_packet(sock, packet):
    sock.sendall((packet + "\n").encode("utf-8"))

# Receives one complete RFMP packet from the server 
def receieve_packet(reader):
    return reader.readline().strip()

# Requests a file from the RFMP server & displays its contents
def open_read(sock,reader):
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
    if response.startswith("DP,"):
        # Remove the DP, packet header
        encoded_content = response[3:]
        
        # Decode Base64 data from the Data Packet
        received_data = base64.b64decode(encoded_content)
        
        # Decrypt the file if secured AES mode is active
        if secure_mode and algorithm == "AES":
            file_content = decrypt_aes(
                received_data,
                session_key
            ).decode("utf-8")
        
        elif secure_mode and algorithm == "Caesar":
            encrypted_text = received_data.decode("latin-1")
        
            file_content = decrypt_caesar(
                encrypted_text,
                caesar_shift
            )
        
        else:
            # Unsecured mode contains normal file bytes
            file_content = received_data.decode("utf-8")
        
        # Display the file contents to the user
        print("\nFile contents received from server:")
        print(file_content)
            
        
        # Receive the final success packet
        status = receieve_packet(reader)
        
        # Display the server status
        print("Server status:", status)
    
    # Check if server returned an error packet
    elif response.startswith("EE,"):
        # Display the error message from the server
        print("Error received from server:", response)
    
    # Catch any unexpected responses from the server
    else:
        print("Unexpected response from server:", response)

# Sends file data to the RFMP server so it can be written to a file
def open_write(sock, reader):
    # Ask the user for the name of the file to create/overwrite on the server 
    file_name = input("Enter the name of the file to create/overwrite on the server: ")
    
    # Ask the user for the text that should be written into the file
    file_content = input("Enter the text to write into the file: ")
    
    # Create the RFMP openWrite command packet
    write_packet = "CM,openWrite," + file_name 
    
    # Send the openWrite command to the server
    send_packet(sock, write_packet)
    
    # Show that the command was sent
    print("Sent:", write_packet)
    
    # Convert file contents into bytes
    file_bytes = file_content.encode("utf-8")
    
    # Encrypt file contents when secured AES mode is active
    if secure_mode and algorithm == "AES":
        data_to_send = encrypt_aes(
            file_bytes,
            session_key
        )
    
    elif secure_mode and algorithm == "Caesar":
        encrypted_text = encrypt_caesar(
            file_content,
            caesar_shift
        )
        
        data_to_send = encrypted_text.encode("latin-1")
    
    else:
        # Unsecured mode sends the original file contents 
        data_to_send = file_bytes
    
    # Base64 encodes the data for RFMP Data packet 
    encoded_content = base64.b64encode(
        data_to_send
    ).decode("ascii")
    
    # Create RFMP Data Packet
    data_packet = "DP," + encoded_content
    
    # Send Data Packet to the server
    send_packet(sock, data_packet)
    
    # Confirm that the file data was sent 
    print("Sent file data to server.")
    
    # Receive the server's final response
    response = receieve_packet(reader)
    
    # Check whether the server successfully wrote the file data
    if response.startswith("SC,"):
        print("Server status:", response)
    
    # Check whether the server returned an error packet
    elif response.startswith("EE,"):
        print("Error received from server:", response)
        
    # Catch any unexpected responses from the server
    else:
        print("Unexpected response from server:", response)

def prompt_command(sock,reader):
        # Show the required and additional supported system commands
        print("\nAvailable prompt commands:")
        print("Required: mkdir, cd, rmdir/rd, del, ren")
        print("Additional: dir, type, copy, move, echo")
            
        # Ask the user to enter the complete command 
        command = input("Enter the full system command to send to the server: ").strip()
        
        # Prevent an empty command from being sent to the server
        if command == "":
                print("Command cannot be empty.")
                return
            
        # Create the RFMP prompt command packet
        prompt_packet = "CM,prompt," + command
            
        # Send the prompt command to the server
        send_packet(sock, prompt_packet)
            
        #Show the packet that was sent
        print("Sent:", prompt_packet)
        
        # Receive the server's response to the prompt command
        response = receieve_packet(reader)
        
        # Check whether the server returned a Data Packet
        if response.startswith("DP,"):
            encoded_data = response[3:]
            received_data = base64.b64decode(encoded_data)
            
            # Decrypt directory listing when secured AES mode is active
            if secure_mode and algorithm == "AES":
                directory_listing = decrypt_aes(
                    received_data,
                    session_key
                ).decode("utf-8")
            
            # Decrypt directory listing when secured Caesar mode is active
            elif secure_mode and algorithm == "Caesar":
                encrypted_text = received_data.decode("latin-1")
                
                directory_listing = decrypt_caesar(
                    encrypted_text,
                    caesar_shift
                ) 
            
            # Unsecured directory listing contains normal bytes
            else:
                directory_listing = received_data.decode("utf-8")
            
            print("\nDirectory listing received from server:")
            print(directory_listing)
            
            # Receive the final success packet from the server
            status = receieve_packet(reader)
            print("Server status:", status)
               
        # Check whether the server successfully executed the command=
        elif response.startswith("SC,"):
                print("Server status:", response)
                
        # Check whether server returned error 
        elif response.startswith("EE,"):
                print("Error received from server:", response)
        
        else:
                print("Unexpected response from server:", response)

HOST = "127.0.0.1" # Server address used for same machine testing
PORT = 8888 # Must match the server port

# Create an IPv4 TCP Client socket 
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to RFMP server 
client_socket.connect((HOST, PORT))

# Confirms that the TCP connection is established
print("Connected to RFMP server.")

# Ask the user whether the RFMP connection should be secured
print("\nConnection mode:")
print("0. Unsecured")
print("1. Secured")

security_choice = input("Choose connection mode (0 or 1): ").strip()

while security_choice not in ("0", "1"):
    print("Invalid choice. Enter 0 for unsecured or 1 for secured.")
    security_choice = input("Choose connection mode (0 or 1): ").strip()

secure_mode = security_choice == "1"

# Values used later when secure file transfer is enabled
algorithm = None
session_key = None
caesar_shift = None

# Create and send the RFMP Start packet
start_packet = "SS,RFMP,v1.0," + security_choice
send_packet(client_socket, start_packet)

print("Sent Start packet:", start_packet)

# Create a text reader so responses can be read one line at a time
client_reader = client_socket.makefile("r", encoding="utf-8")

# Receive the server's Confirm-Connection packet
response = receieve_packet(client_reader)

print("Received from server:", response)

connection_ready = False

# Unsecured connection
if not secure_mode and response == "CC":
    print("Unsecured RFMP connection established successfully.")
    connection_ready = True

# Secured connection
elif secure_mode and response.startswith("CC,"):
    # Extract the server's Base64-encoded RSA public key
    encoded_server_key = response.split(",", 1)[1]

    # Convert the server public key back into an RSA key object
    server_key_bytes = base64.b64decode(encoded_server_key)
    server_public_key = rsa.PublicKey.load_pkcs1(server_key_bytes)

    print("Server RSA public key received successfully.")

    # Ask which encryption algorithm should be used
    print("\nEncryption algorithm:")
    print("1. AES")
    print("2. Caesar")

    algorithm_choice = input(
        "Choose encryption algorithm (1 or 2): "
    ).strip()

    while algorithm_choice not in ("1", "2"):
        print("Invalid choice. Enter 1 for AES or 2 for Caesar.")
        algorithm_choice = input(
            "Choose encryption algorithm (1 or 2): "
        ).strip()

    algorithm = "AES" if algorithm_choice == "1" else "Caesar"

    # Generate the client's RSA public/private key pair
    client_public_key, client_private_key = create_rsa_keys()

    # Generate the required 16-byte session key
    session_key = create_session_key()

    # Encrypt the session key using the server's RSA public key
    encrypted_session_key = encrypt_rsa(
        session_key,
        server_public_key
    )

    # Convert encrypted session key to Base64
    encoded_session_key = base64.b64encode(
        encrypted_session_key
    ).decode("ascii")

    # Convert client public RSA key to PEM and then Base64
    client_public_key_bytes = client_public_key.save_pkcs1()

    encoded_client_key = base64.b64encode(
        client_public_key_bytes
    ).decode("ascii")

    username = input("Enter username: ").strip()

    while username == "":
        print("Username cannot be empty.")
        username = input("Enter username: ").strip()

    # Create the RFMP Encryption Packet
    encryption_packet = (
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
    send_packet(client_socket, encryption_packet)

    # Calculate Caesar shift now in case Caesar was selected
    caesar_shift = session_key[0] % 25 + 1

    print("Sent Encryption Packet using", algorithm)
    print("Secured RFMP connection established successfully.")

    connection_ready = True

# Run the normal RFMP menu only after setup succeeds
if connection_ready:
    
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
        
        # Run a system command on the server
        if choice == "1":
            prompt_command(client_socket, client_reader)
        
        # Read a file from the server
        elif choice == "2":
            open_read(client_socket, client_reader)
        
        # Write a file to the server
        elif choice == "3":
            open_write(client_socket, client_reader)
            
        # End the RFMP server session and close the client
        elif choice == "4":
            end_packet = "End"
            send_packet(client_socket, end_packet)
            print("Sent close session packet:", end_packet)
            break
        
        else:
            print("Invalid choice. Please select a valid option.")  
            
else:
    print("Failed to establish RFMP connection:", response)

# Close the reader
client_reader.close()

# Close the client socket to terminate the TCP connection
client_socket.close()

# Confirm that client session has ended
print("Connection to RFMP server closed. Client session ended.")