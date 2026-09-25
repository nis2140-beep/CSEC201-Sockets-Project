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


    # Start-Packet (client to server) (Set-up phase)
    client_reader = client_socket.makefile("r", encoding="utf-8")
    message = client_reader.readline().strip()
    print("Client sent: ", message)
    
    fields = message.split(",")
    
    if fields == ["SS", "RFMP", "v1.0", "0"]:
        client_socket.sendall("CC\n".encode("utf-8"))
        print("Unsecured connection confirmed")
        
        
        # Keeping client connected until "End"
        for next_packet in client_reader:
            next_packet = next_packet.strip()
            
            if next_packet == "End":
                print("Client has ended the session")
                break
                
            client_socket.sendall("EE,2,Unknown packet\n".encode("utf-8"))
                
        print("Client has been disconnected")
    else:
        client_socket.sendall("EE,4,Invalid setup packet\n".encode("utf-8"))
        print("Invalid setup packet:", message)
        
    client_reader.close()
    client_socket.close()


