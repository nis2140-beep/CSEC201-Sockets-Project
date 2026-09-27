import socket # Provides TCP socket functions 
import base64 # Used to decode file data received from the server

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
        
        # Decode the Base64-encoded file content
        file_content = base64.b64decode(encoded_content).decode("utf-8")
        
        # Display the file contents
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
    
    # Convert the file text into bytes and encode it using Base64
    encoded_content = base64.b64encode(file_content.encode("utf-8")).decode("ascii")
    
    # Create the RFMP Data Packet containing the encoded file contents
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
        
HOST = "127.0.0.1" # Server address used for same machine testing
PORT = 8888 # Must match the server port

# Create an IPv4 TCP Client socket 
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to RFMP server 
client_socket.connect((HOST, PORT))

# Confirms that the TCP connection is established
print("Connected to RFMP server.")

# Create & send the unsecured RFMP Start packet to the server
start_packet = "SS,RFMP,v1.0,0"
send_packet(client_socket, start_packet)


# Show the packet without printing newline character
print("Sent Start packet:", start_packet.strip())

# Create a text reader so that responses can be read one line at a time
client_reader = client_socket.makefile("r", encoding="utf-8")

# Read the server's Confirm-Connection packet
response = receieve_packet(client_reader)

# Display server's response
print("Received from server:", response)

# Check whether the server has confirmed the connection 
if response == "CC":
    print("Unsecured RFMP connection established successfully.")
    
    # Keep showing the menu until the user chooses to end the session 
    while True:
        # Display the menu options
        print("\nRFMP Client Menu:")
        print("1. openRead - Read a file from the server")
        print("2. openWrite - Write a file to the server")
        print("3. End session - Close the connection and exit")
        
        # Ask the user to choose an operation 
        choice = input("Enter your choice (1, 2, or 3): ")
        
        # Read a file from the server 
        if choice == "1":
            open_read(client_socket, client_reader)
        
        # Write data to a file on the server
        elif choice == "2":
            open_write(client_socket, client_reader)
        
        # End the RFMP session 
        elif choice == "3":
            end_packet = "End"
            send_packet(client_socket, end_packet)
            print("Sent closing packet:", end_packet)
            break
        
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
            
else:
    print("Failed to establish unsecured RFMP connection:", response)

# Close the reader
client_reader.close()

# Close the client socket to terminate the TCP connection
client_socket.close()

# Confirm that client session has ended
print("Connection to RFMP server closed. Client session ended.")
