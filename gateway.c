#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>


#define P 10000
#define SERVER_IP_ADDRESS "127.0.0.1"

int main(int argc, char ** argv)
{
    int yes = 1;

    //The user enter an IP to ping
    char * destination_ip = argv[1];
	printf("IP: %s\n", argv[1]);

    int s_P = -1;
    // Create socket
	if ((s_P = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) 
	{
		printf("Could not create socket : %d", errno);
		close(s_P);
			return -1;
	}
	printf("Creates sock p\n");
	
	/*P*/

    //Setup the server address structure
    struct sockaddr_in serverAddress;
	memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(P);
	int rval = inet_pton(AF_INET, (const char*)SERVER_IP_ADDRESS, &serverAddress.sin_addr);
	if (rval <= 0)
	{
		printf("inet_pton() failed");
		close(s_P);
		return -1;
	}

	//Setup the server address structure //we got in terminal.
    struct sockaddr_in serverAddress_P1;
	memset(&serverAddress_P1, 0, sizeof(serverAddress_P1));
	serverAddress_P1.sin_family = AF_INET;
	serverAddress_P1.sin_port = htons(P+1);
	int rval2 = inet_pton(AF_INET, (const char*)SERVER_IP_ADDRESS, &serverAddress_P1.sin_addr);
	if (rval2 <= 0)
	{
		printf("inet_pton() 2 failed");
		close(s_P);
		return -1;
	}


	//Bind to s_P
	if (bind(s_P, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1)
	{
		printf("bind() failed with error code : %d", errno);
		// TODO: cleanup the socket;
		close(s_P1);
		close(s_P);
		return -1;
	}

	/*P+1*/

    int s_P1 = -1;
    // Create socket
	if ((s_P1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) 
	{
		printf("Could not create socket : %d", errno);
		close(s_P1);
		close(s_P);
			return -1;
	}
	printf("Creates sock p1\n");

	//Bind to s_P1
	if (bind(s_P1, (struct sockaddr *)&serverAddress_P1, sizeof(serverAddress_P1)) == -1)
	{
		printf("bind() failed with error code : %d", errno);
		// TODO: cleanup the socket;
		close(s_P1);
		close(s_P);
		return -1;
	}
	printf("After bind(). Waiting for clients\n");

	// setup Client address structure
	struct sockaddr_in clientAddress;
	socklen_t clientAddressLen = sizeof(clientAddress);

	memset((char *)&clientAddress, 0, sizeof(clientAddress));

	//listening for data from P
	while (1)
	{
		fflush(stdout);

		// zero client address 
		memset((char *)&clientAddress, 0, sizeof(clientAddress));
		clientAddressLen = sizeof(clientAddress);

		char buffer[80] = { '\0' };
		//clear the buffer by filling null, it might have previously received data
		memset(buffer, '\0', sizeof (buffer));

		int recv_len = -1;

		//try to receive some data, this is a blocking call
		if ((recv_len = recvfrom(s_P, buffer, sizeof(buffer) -1, 0, (struct sockaddr *) &clientAddress, &clientAddressLen)) == -1)
		{
			printf("recvfrom() failed with error code : %d", errno);
			close(s_P1);
			close(s_P);
			break;
		}

		char clientIPAddrReadable[32] = { '\0' };
		inet_ntop(AF_INET, &clientAddress.sin_addr, clientIPAddrReadable, sizeof(clientIPAddrReadable));

		//print details of the client/peer and the data received
		printf("Received packet from %s:%d\n", clientIPAddrReadable, ntohs(clientAddress.sin_port));
		printf("Data is: %s\n", buffer);

		if(recv_len > 0)
		{
			float random = ((float)rand())/((float)RAND_MAX);
			printf("Got packet!\n");
			printf("random = %f\n", random);
			if(random > 0.5)
			{
				//now reply to the Client
				int send = sendto(s_P1, buffer, recv_len, 0, (struct sockaddr*) &serverAddress_P1, sizeof(serverAddress_P1));
				if (send == -1)
				{
					printf("sendto() failed with error code :  %d", errno);
					close(s_P1);
					close(s_P);
					break;
				}
				printf("send: %d\n",send);
				printf("sent packet to P+1!!!\n");
			}

		}
		
	}

	close(s_P1);
	close(s_P);

    return 0;
}