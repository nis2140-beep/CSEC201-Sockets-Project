#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define HOST "127.0.0.1"
#define PORT 8888

int main(void)
{
    WSADATA wsa_data;
    SOCKET client_socket;
    struct sockaddr_in server_address;

    char response[1024];
    int bytes_received;

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
    bytes_received = recv(client_socket, response, sizeof(response) - 1, 0);

    if (bytes_received <= 0)
    {
        printf("Failed to receive server response.\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    /* Convert the received bytes into a C string */
    response[bytes_received] = '\0';

    /* Remove newline character if present  from the received packet*/
    response[strcspn(response, "\r\n")] ='\0';

    printf("Received from server: %s\n", response);

    /* Verify that the server confirmed the connection */
    if (strcmp(response, "CC") == 0)
    {
        printf("Unsecured RFMP connection established.\n");
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

