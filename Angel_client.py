import socket # Provides TCP socket functions 

# Sends 1 RFMP packet followed by a newline
def send_packet(sock, packet):
    sock.sendall((packet + "\n").encode("utf-8"))

# Receives one complete RFMP packet from the server 
def receieve_packet(reader):
    return reader.readline().strip()

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
    
    # Create the RFMP closing packet
    end_packet = "End"
    send_packet(client_socket, end_packet)  
    
    print("Sent closing packet:", end_packet)

else:
    print("Failed to establish unsecured RFMP connection:", response)

# Close the reader
client_reader.close()

# Close the client socket to terminate the TCP connection
client_socket.close()

# Confirm that client session has ended
print("Connection to RFMP server closed. Client session ended.")
