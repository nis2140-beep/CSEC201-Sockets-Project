import socket # Provides TCP socket functions 

HOST = "127.0.0.1" # Server address used for same machine testing
PORT = 8888 # Must match the server port

# Create an IPv4 TCP Client socket 
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to RFMP server 
client_socket.connect((HOST, PORT))

# Confirms that the TCP connection is established
print("Connected to RFMP server.")

# Create an unsecured RFMP Start packet
start_packet = "SS,RFMP,v1.0,0\n"

# Send the Start packet to the server as UTF-8 encoded bytes
client_socket.sendall(start_packet.encode("utf-8"))

# Show the packet without printing newline character
print("Sent Start packet:", start_packet.strip())

# Create a text reader so that responses can be read one line at a time
client_reader = client_socket.makefile("r", encoding="utf-8")

# Read the server's Confirm-Connection packet
response = client_reader.readline().strip()

# Display server's response
print("Received from server:", response)

# Check whether the server has confirmed the connection 
if response == "CC":
    print("Unsecured RFMP connection established successfully.")
else:
    print("Failed to establish unsecured RFMP connection:", response)
    
# Close the reader
client_reader.close()

# Close the client socket
client_socket.close()
