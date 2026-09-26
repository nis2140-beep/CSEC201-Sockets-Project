import socket # Provides TCP socket functions 

HOST = "127.0.0.1" # Server address used for same machine testing
PORT = 8888 # Must match the server port

# Create an IPv4 TCP Client socket 
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to RFMP server 
client_socket.connect((HOST, PORT))

# Confirms that the TCP connection is established
print("Connected to RFMP server.")

# Closes the socket for this first development milestone
client_socket.close()