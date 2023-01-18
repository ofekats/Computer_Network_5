#include <stdio.h>
#include <stdlib.h> 
#include <errno.h> 
#include <string.h> 
#include <sys/types.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_IP_ADDRESS "127.0.0.1"
#define SERVER_PORT 9000

int main()
{

	int s = -1;
	char bufferReply[80] = { '\0' };
	char message[] = "Good morning, Vietnam\n";
	int messageLen = strlen(message) + 1;

	// Create socket
	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) // In Windows -1 is SOCKET_ERROR
	{
		printf("Could not create socket : %d", errno);
		return -1;
	}

	// Setup the server address structure.
	// Port and IP should be filled in network byte order (learn bin-endian, little-endian)
	//
	struct sockaddr_in serverAddress;
	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(SERVER_PORT);
	int rval = inet_pton(AF_INET, (const char*)SERVER_IP_ADDRESS, &serverAddress.sin_addr);
	if (rval <= 0)
	{
		printf("inet_pton() failed");
		return -1;
	}
	while(1)
    {
        //send the message
        if (sendto(s, message, messageLen, 0, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) == -1)
        {
            printf("sendto() failed with error code  : %d", errno);
                return -1;
        }
        printf("send packet!\n");
    }
	

	// struct sockaddr_in fromAddress;
	// //Change type variable from int to socklen_t: int fromAddressSize = sizeof(fromAddress);
	// socklen_t fromAddressSize = sizeof(fromAddress);

	// memset((char *)&fromAddress, 0, sizeof(fromAddress));

	// // try to receive some data, this is a blocking call
	// if (recvfrom(s, bufferReply, sizeof(bufferReply) -1, 0, (struct sockaddr *) &fromAddress, &fromAddressSize) == -1)
	// {
	// 	printf("recvfrom() failed with error code  : %d", errno);
	// 	return -1;
	// }

	// printf(bufferReply);
	close(s);


    return 0;
}

