import socket

# Creating the listening socket
host = "127.0.0.1"
port = 8888

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((host,port))
server_socket.listen(5)

print("RFMP server is listening on port", port)


# Accepting clients
while True:
    client_socket, address = server_socket.accept()
    print("Client is connected:", address)
    
    client_socket.close()


# 

