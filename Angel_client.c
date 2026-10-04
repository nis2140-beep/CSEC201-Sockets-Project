#include <stdio.h> // provides input/output functions like printf and fgets
#include <string.h> // provides string functions like strlen 
#include <winsock2.h> // provides Windows socket networking functions
#include <ws2tcpip.h> // provides extra TCP/IP networking definitions

#define HOST "127.0.0.1" // server IP address - same computer
#define PORT 8888 // port number, must match the python server

/* Receives one complete newline-terminated RFMP packet */
int receive_packet(SOCKET sock, char *buffer, int buffer_size) // defines a helper function that receives one RFMP packet from the server, SOCKET sock is the TCP connection, char *buffer is where the receiving packet will be stored, buffer_size tells the function how much space is available, int means the function returns a number, char stores one character
{
    int total = 0;
    char character; // unlike Python, this manually builds the packet character by character until it reaches \n. char *buffer is a pointer to the memory where packet text is stored.

    while (total < buffer_size - 1) // keep reading until there is space in the buffer. buffer_size-1 leaves one position for the C string ending character '\0'
    {
        int received = recv(sock, &character, 1, 0); // recv reads from the socket, &character means "store the received byte at memory address of character", and 1 means receive only one byte at a time
        // reading one character at a time makes it easy to detect the newline that marks the end of the RFMP packet. 

        if (received <= 0) // check if the connection closed or recv() failed, if recv() returns 0 or less, the connection was closed or an error happened, so function stops
        {
            return received; // immediately exits the function and sends that value back to the code that called receive_packet()
        }

        if (character == '\n') // check if RFMP packet-ending newline was received
        {
            break; // stop while loop, and exits
        }

        if (character != '\r') // ignore this extra line-ending character
        {
            buffer[total++] = character; // every normal character gets added into buffer, where the client is building the full message
        }
    }

    buffer[total] = '\0'; // marks where the C string ends
    return total; // return how many characters were received
}


/* Converts one Base64 character to its numerical matching value from 0 to 63 */
int base64_value(char character) // receives one Base64 character and returns its numerical value
{
    if (character >= 'A' && character <= 'Z') // checks if the character is an uppercase letter A-Z
        return character - 'A'; // converts A-Z into Base64 values 0-25, for example A - A = 0 and B - A = 1

    if (character >= 'a' && character <= 'z') // checks if the character is a lowercase a-z
        return character - 'a' + 26; // Base64 lowercase letters start at 26

    if (character >= '0' && character <= '9') // checks if the character is a number 0-9
        return character - '0' + 52; // checks whether it is a digit character, then converts that digit into its correct Base64 value

    if (character == '+') // checks if the Base64 character is +
        return 62; // + always represents Base64 value 62

    if (character == '/') // checks if the Base64 character is /
        return 63; // / alwyas represents Base64 value 63

    return -1; // return -1 if the character is not valid
}


/* Decodes Base64 file data received from the RFMP server */ // uses all the translated numeric values to rebuild the original file
int decode_base64(const char *input, unsigned char *output, int output_size) // this function takes the entire Base64 string from the server and converts it back into real file data, input is the Base64 text, output is where the decoded file bytes will be stored, output_size tells the function how much space that output area has
{
    int value = 0; // temporary storage used while rebuilding the original bytes
    int bits = -8; // tracks when enough Base64 bits have been collected to make a full byte
    int output_length = 0; // counts how many decoded bytes have been written into output

    while (*input != '\0' && *input != '=') // keep looping until Base64 text ends or reaches '=' padding
    {
        int decoded_value = base64_value(*input++); // convert the current Base64 character to its numeric value, then move to the next character
        // this loop goes through the Base64 text one character at a time, *input means "the character we are currently looking at". the loop continues until it reaches '\0' which means the end of the C string or = which Base64 uses as padding at the end.

        if (decoded_value < 0) // heck whether base64_value found an invalid Base64 character
        {
            return -1; // stop decoding and report that the Base64 data was invalid
            // normal Base64 values are 0-63, anything below 0 means something went wrong & base65_value() returns -1 if the character is not valid Base64.
        }

        // Each Base64 character gives 6 bits, but a normal byte needs 8 bits, so the code keeps collecting 6-bit pieces until it has enough to make one full byte
        value = (value << 6) | decoded_value; // shift previous Base64 data left by 6 bits, then add new 6 bit value
        bits += 6; // record that 6 more bits have now been collected

        if (bits >= 0) // check if enough bits have been collected to make one full 8 bit byte
        {
            if (output_length >= output_size - 1) // make sure output buffer still has free space
            {
                return -1; // stop if there is no room left
            }

            // take the next 8 bits from the Base64 data, turn them into one byte and store that byte in the decoded file, then move to the next output position
            output[output_length++] = // output is where the decoded file bytes are being stored, output_length tells us which position we are currently filling, ++ means increase output_length, (unsigned char) is one byte whose value is treated as 0-255, value is the temporary number holding the Base64 bits we have collected so far, >> means shift bits to the right, & is called bitwise AND, it helps us keep the bits we want, 0xFF means keep only the last 8 bits
                (unsigned char)((value >> bits) & 0xFF); 

            bits -= 8; // remove the 8 bits that were just used
        }
    }

    output[output_length] = '\0'; // add a null terminator so C knows exactly where the decoded file data ends
    return output_length; // return the total number of original bytes successfully rebuilt from the Base64 data
}

int main(void) // main function, program execution starts here
{
    WSADATA wsa_data; // stores info about the initialized Winsock library
    SOCKET client_socket; // will store the TCP client socket
    struct sockaddr_in server_address; // will store the server's IPv4 address and port

    char response[8192]; // buffer for packets received from server
    int bytes_received; // stores how many bytes were received

    char file_name[256]; // stores filename entered by the user
    char read_packet[512]; // stores the CM,openRead... packet
    unsigned char file_content[6144]; // stores the decoded file contents
    int decoded_length; // stores how many bytes Base64 decoding produced


    /* Initialize Winsock so Windows networking functions can be used */
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) { // Start Winsock version 2.2 and check if initialization failed
        printf("Failed to initialize Winsock.\n"); // show an error message if winsock could not start
        return 1; // end the program because networking cannot continue
    }

    /* Create an IPv4 TCP client socket */
    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // create a TCP socket that uses IPv4

    if (client_socket == INVALID_SOCKET) { // check whether socket creation failed
        printf("Failed to create socket.\n"); // show an error message
        WSACleanup(); // shut down Winsock because we are stopping
        return 1; // end the program
    }

    /* Configure the RFMP server address */
    server_address.sin_family = AF_INET; // tell C that the server address uses IPv4 
    server_address.sin_port = htons(PORT); // convert port 8888 into network byte order because network protocols expect numbers like ports in network byte order
    server_address.sin_addr.s_addr = inet_addr(HOST); // convert local host 127.0.0.1 into numeric IP format the socket needs

    /* Connect the client to the RFMP server */
    // connect() is the point where the C client actually tries to open a TCP connection to the Python server.
    if (connect(client_socket, // the socket we created earlier
        (struct sockaddr *)&server_address, // the server address we want to connect to
        sizeof(server_address)) == SOCKET_ERROR) // check whether the connection failed
    {
        printf("Failed to connect to the server.\n"); // show an error message 
        closesocket(client_socket); // close socket because it cannot be used
        WSACleanup(); // shut down winsock properly
        return 1; // end the program

    }

    printf("Connected to RFMP server.\n"); // tells user that TCP connection to server succeeded

    /* Create the unsecured RFMP Start packet*/
    const char *start_packet = "SS,RFMP,v1.0,0\n"; // Build the RFMP setup packet, 0 means unsecured mode

    /* Send the Start packet to the server */
    if (send(client_socket, start_packet, (int)strlen(start_packet), 0) == SOCKET_ERROR) // send the full SS packet and check whether sending failed
    {
        printf("Failed to send RFMP Start packet.\n"); // show an error if the packet could not be sent
        closesocket(client_socket); // close the TCP socket
        WSACleanup(); // shut down Winsock
        return 1; // end the program
    }

    printf("Sent Start packet: SS,RFMP,v1.0,0\n"); // show the user that the start packet was sent

    /* Receive the server's Confirm-Connection Packet*/
    bytes_received = receive_packet(
        client_socket, // receive from this connected socket
        response, // stores the server's packet inside the response buffer
        sizeof(response) // tells receive_packet() how large the response buffer is so it does not write past the buffer
    );

    if (bytes_received <= 0) // check whether not response arrived or receiving failed, if bytes received are greater than 0, data was received successfully, if it is 0 or less, the server closed the connection or something went wrong while receiving
    {
        printf("Failed to receive server response.\n"); // show the receive error
        closesocket(client_socket); // close the client socket
        WSACleanup(); // clean up winsock
        return 1; // stop program
    }

    printf("Received server response: %s\n", response); // Display the packet received from the server

    /* Verify that the server confirmed the connection */
    if (strcmp(response, "CC") == 0) // compare the server response with the expected unsecured confirm-connection packet, if they are the same, strcmp() returns 0 so the condition is true and the client knows the unsecured RFMP setup succeeded
    {
        printf("Unsecured RFMP connection established.\n"); // confirm that RFMP setup succeeded

        /* Ask the user which file should be read from the server */
        printf("Enter the name of the file to read from the server: ");

        if (fgets(file_name, sizeof(file_name), stdin) == NULL) // read the filename safely into file_name and check for input failure. fgets() takes what the user types and stores it inside the file_name array. sizeof(file_name) tells fgets() maximum amount of space available so it does not overflow the array and stdin means input is coming from the keyboard
        {
            printf("Failed to read file name from input.\n"); // show an error if keyboard input failed
        }
        else
        {
            /* Remove the newline entered by user */
            file_name[strcspn(file_name, "\r\n")] = '\0'; // find the first \r or \n and replace it with the C string ending marker

            /* Create RFMP openRead command packet*/
            snprintf( // builds formatted text safely inside read_packet
                read_packet, // store the finished packet inside read_packet
                sizeof(read_packet), // maximum amount of space available inside read_packet
                "CM,openRead,%s\n", // RFMP packet format, %s will be replaced by filename
                file_name // filename entered by the user
            );

            /* Send openRead packet to the server */
            if (send(
                client_socket, // send through the connected client
                read_packet, // send the CM,openRead,... packet we just built
                (int)strlen(read_packet), // tell send() exactly how many bytes are in the packet
                0 // use normal send behavior
            ) == SOCKET_ERROR) // check whether sending failed
            {
                printf("Failed to send openRead request. \n"); // show an error if packet could not be sent
            }
            else
            {
                printf("Send: CM,openRead,%s\n", file_name); // show which openRead request was sent

                /* Receive server's first reponse*/
                bytes_received = receive_packet(
                    client_socket, // receive from the same connected socket
                    response, // store the server's packet inside response
                    sizeof(response) // tells the function how much space response has
                );

                if (bytes_received > 0) // continue only if a server response was successfully received
                {
                    /* Check whether server returned a Data Packet  */
                    if (strncmp(response, "DP,", 3) == 0) // checks whether the first 3 characters are exactly "DP,"
                    {
                        /* Decode the Base64 file contents after DP, */
                        decoded_length = decode_base64(
                            response + 3, // skip the first 3 characters "DP," and start at the Base64 data
                            file_content, // store the decoded/original file bytes here
                            sizeof(file_content) // max space available for the decoded file
                        );

                        if (decoded_length >= 0) // check that Base64 decoding succeeded
                        {
                         printf("\nFile contents received from server:\n"); // print a heading
                         printf("%s\n", file_content); // display the decoded file contents
                         
                         /* Receive the final Success Packet */
                         bytes_received = receive_packet( 
                            client_socket, // read the next RFMP packet from the same server connection
                            response, // store that packet inside response buffer
                            sizeof(response) // tell the function maximum size of the response buffer
                        );

                        if (bytes_received > 0) // only continue if a packet was actually received
                        {
                            printf("Server status: %s\n", response); // display the server's final status message
                        }
                    }
                    else // runs if decode_base64() returned an error
                    {
                        printf("Failed to decode the file data.\n"); // print the error message telling user that Base64 data could not be rebuilt
                    }  
                }
                else if (strncmp(response, "EE,", 3) == 0) // check whether server returned an error/exception packet
                {
                   printf("Error received from server: %s\n", response); // display full server error
                 }
                 else // runs if error was neither DP nor EE
                    {
                        printf("Unexpected response from server: %s\n", response); // print the unknown packet for debugging
                    }
            }
        }
    }
    /* Create & send the RFMP closing packet */
    const char *end_packet = "End\n"; // create the RFMP End packet; \n marks the end of the packet

    if (send(client_socket, end_packet, (int)strlen(end_packet), 0) == SOCKET_ERROR) // send End to the server and check if sending failed
    {
        printf("Failed to send RFMP closing packet.\n"); // send an error if End could not be sent
    }
    else
    {
        printf("Sent closing packet: End\n"); // confirm that the End packet was sent successfully
    }
}
         
else // runs if the server response was not the expected "CC"
{
    printf("Failed to establish unsecured RFMP connection.\n"); // tells the user RFMP setup failed
}
    /* Close the TCP connection */
    closesocket(client_socket); // close actual TCP connection
    WSACleanup(); // shut down Winsock networking system

    return 0; // end program successfully
}

