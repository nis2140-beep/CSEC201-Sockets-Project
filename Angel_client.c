#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define HOST "127.0.0.1"
#define PORT 8888

int main(void)
{
    WSADATA wsa_data;
    SOCKET client_socket;
    struct sockaddr_in server_address;

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

    /* Close the TCP connection */
    closesocket(client_socket);
    WSACleanup();

    return 0;
}

