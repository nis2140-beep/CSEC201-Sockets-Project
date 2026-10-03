#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define HOST "127.0.0.1"
#define PORT 8888

/* Receives one complete newline-terminated RFMP packet */
int receive_packet(SOCKET sock, char *buffer, int buffer_size)
{
    int total = 0;
    char character;

    while (total < buffer_size - 1)
    {
        int received = recv(sock, &character, 1, 0);

        if (received <= 0)
        {
            return received;
        }

        if (character == '\n')
        {
            break;
        }

        if (character != '\r')
        {
            buffer[total++] = character;
        }
    }

    buffer[total] = '\0';
    return total;
}


/* Converts one Base64 character to its numerical value */
int base64_value(char character)
{
    if (character >= 'A' && character <= 'Z')
        return character - 'A';

    if (character >= 'a' && character <= 'z')
        return character - 'a' + 26;

    if (character >= '0' && character <= '9')
        return character - '0' + 52;

    if (character == '+')
        return 62;

    if (character == '/')
        return 63;

    return -1;
}


/* Decodes Base64 file data received from the RFMP server */
int decode_base64(const char *input, unsigned char *output, int output_size)
{
    int value = 0;
    int bits = -8;
    int output_length = 0;

    while (*input != '\0' && *input != '=')
    {
        int decoded_value = base64_value(*input++);

        if (decoded_value < 0)
        {
            return -1;
        }

        value = (value << 6) | decoded_value;
        bits += 6;

        if (bits >= 0)
        {
            if (output_length >= output_size - 1)
            {
                return -1;
            }

            output[output_length++] =
                (unsigned char)((value >> bits) & 0xFF);

            bits -= 8;
        }
    }

    output[output_length] = '\0';
    return output_length;
}

int main(void)
{
    WSADATA wsa_data;
    SOCKET client_socket;
    struct sockaddr_in server_address;

    char response[8192];
    int bytes_received;

    char file_name[256];
    char read_packet[512];
    unsigned char file_content[6144];
    int decoded_length;


    /* Initialize Winsock */
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("Failed to initialize Winsock.\n");
        return 1;
    }

    /* Create an IPv4 TCP client socket */
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (client_socket == INVALID_SOCKET) {
        printf("Failed to create socket.\n");
        WSACleanup();
        return 1;
    }

    /* Configure the RFMP server address */
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);
    server_address.sin_addr.s_addr = inet_addr(HOST); 

    /* Connect to the RFMP server */
    if (connect(client_socket,
        (struct sockaddr *)&server_address,
        sizeof(server_address)) == SOCKET_ERROR)
    {
        printf("Failed to connect to the server.\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;

    }

    printf("Connected to RFMP server.\n");

    /* Create the unsecured RFMP Start packet*/
    const char *start_packet = "SS,RFMP,v1.0,0\n";

    /* Send the Start packet to the server */
    if (send(client_socket, start_packet, (int)strlen(start_packet), 0) == SOCKET_ERROR)
    {
        printf("Failed to send RFMP Start packet.\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    printf("Sent Start packet: SS,RFMP,v1.0,0\n");

    /* Receive the server's Confirm-Connection Packet*/
    bytes_received = receive_packet(
        client_socket,
        response,
        sizeof(response)
    );

    if (bytes_received <= 0)
    {
        printf("Failed to receive server response.\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    printf("Received server response: %s\n", response);

    /* Verify that the server confirmed the connection */
    if (strcmp(response, "CC") == 0)
    {
        printf("Unsecured RFMP connection established.\n");

        /* Ask the user which file should be read from the server */
        printf("Enter the name of the file to read from the server: ");

        if (fgets(file_name, sizeof(file_name), stdin) == NULL)
        {
            printf("Failed to read file name from input.\n");
        }
        else
        {
            /* Remove the newline entered by user */
            file_name[strcspn(file_name, "\r\n")] = '\0';

            /* Create RFMP openRead command packet*/
            snprintf(
                read_packet,
                sizeof(read_packet),
                "CM,openRead,%s\n",
                file_name
            );

            /* Send openRead packet to the server */
            if (send(
                client_socket,
                read_packet,
                (int)strlen(read_packet),
                0
            ) == SOCKET_ERROR)
            {
                printf("Failed to send openRead request. \n");
            }
            else
            {
                printf("Send: CM,openRead,%s\n", file_name);

                /* Receive server's first reponse*/
                bytes_received = receive_packet(
                    client_socket,
                    response,
                    sizeof(response)
                );

                if (bytes_received > 0)
                {
                    /* Check whether server returned a Data Packet  */
                    if (strncmp(response, "DP,", 3) == 0)
                    {
                        /* Decode the Base64 file contents after DP, */
                        decoded_length = decode_base64(
                            response + 3,
                            file_content,
                            sizeof(file_content)
                        );

                        if (decoded_length >= 0)
                        {
                         printf("\nFile contents received from server:\n");
                         printf("%s\n", file_content);
                         
                         /* Receive the final Success Packet */
                         bytes_received = receive_packet(
                            client_socket,
                            response,
                            sizeof(response)
                        );

                        if (bytes_received > 0)
                        {
                            printf("Server status: %s\n", response);
                        }
                    }
                    else
                    {
                        printf("Failed to decode the file data.\n");
                    }  
                }
                else if (strncmp(response, "EE,", 3) == 0)
                {
                   printf("Error received from server: %s\n", response);
                 }
                 else
                    {
                        printf("Unexpected response from server: %s\n", response);
                    }
            }
        }
    }
    /* Create & send the RFMP closing packet */
    const char *end_packet = "End\n";

    if (send(client_socket, end_packet, (int)strlen(end_packet), 0) == SOCKET_ERROR)
    {
        printf("Failed to send RFMP closing packet.\n");
    }
    else
    {
        printf("Sent closing packet: End\n");
    }
}
         
else
{
    printf("Failed to establish unsecured RFMP connection.\n");
}
    /* Close the TCP connection */
    closesocket(client_socket);
    WSACleanup();

    return 0;
}

