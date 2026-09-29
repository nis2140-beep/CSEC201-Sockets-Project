import socket
import base64
import binascii
import os

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
                
                data_packet = client_reader.readline().strip()
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
                else:
                    client_socket.sendall(b"EE,2,Unknown prompt command\n")
            else:
                client_socket.sendall("EE,2,Unknown packet\n".encode("utf-8"))
                
        print("Client has been disconnected")
    else:
        client_socket.sendall("EE,4,Invalid setup packet\n".encode("utf-8"))
        print("Invalid setup packet:", message)
        
    client_reader.close()
    client_socket.close()


