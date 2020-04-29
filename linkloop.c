/*
* Original Author: Ruben Rodriguez
* Created: 2020.04.29
* 
* Program to check conectivity between two host using datalink packets.
* Program modes:
* 1) Link-test: sends special link-test packet to MAC specified and waits for a link-up response sent by this utility running in link-up mode.
* If there are no response in 10 seconds, another link-test is sent until program is stopped by SIGINT.
* 2) Link-up: waits for an special packet challenge, replies to it and keeps running for processing further replies.
* Usage: 
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h> 
#include <unistd.h>

#include <sys/types.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

unsigned char *deviceName;

/*
 * printPacket(const u_char *packet, int size)
 * 
 * Prints the packet as hex
 *
 */
void printPacket(const u_char *packet, int size){

	for(int i = 0; i < size; i++){
		printf("%x", packet[i]);
	}
	printf("\n\n");

}

/*
 * createPacket(unsigned char *packet, unsigned char *data, unsigned int *srcMac, unsigned int *dstMac, int packetSize, int dataSize)
 * 
 * Forges the a packet to be send
 *
 */
void createPacket(unsigned char *packet, unsigned char *data, unsigned int *srcMac, unsigned int *dstMac, int packetSize, int dataSize){
	
	int i, j;
	int index =0;

	/* Zeroing packet */
	for(i = 0; i < packetSize; i++){
		packet[i] = 0x00;
	}

	printf("Forging packet with data size %d\n", dataSize);

	/* Chek if data fits into packet */
	if((packetSize - 14) < dataSize){
		printf("Can't fit data %d bytes into packet size %d\n", dataSize, packetSize);
		exit(1);
	}

	/* Dest MAC */
	for(i = 0; i < 6; i++){
		packet[i] = dstMac[i];
	}
	
	/* Src MAC address */
	index = 0;
	for(i = 6; i < 12; i ++){
		packet[i] = srcMac[index];
		index++;
	}
	
	/* EtherType 0x8005 */
	packet[12] = 0x80;
	packet[13] = 0x05;

	/* Filling Data section of datagram */
	index = 0;
	for(i = 14; i < (14 + dataSize); i++)
	{	
		packet[i] = data[index];
		index++;
	}

	int aux = i;
	for(i = aux; i < packetSize; i++)
	{	
		packet[i] = 0x00;
	}

	printf("Forged packet:  ");
	printPacket(packet, packetSize);

}

/*
 * sendPacket(unsigned char *packet, int size)
 *
 * Sends a packet using the device mapped
 *
 */
void sendPacket(unsigned char *packet, int size) {
	
	printf("Sending packet using %s\n", deviceName);

	char errbuf[PCAP_ERRBUF_SIZE]; //The pcap error string buffer
	pcap_t* pcapStatus;
	pcapStatus = pcap_open_live(deviceName, BUFSIZ, 0, 1, errbuf);
	if (pcapStatus == (pcap_t *) NULL) {
	    printf("Call to pcap_open_live() returned error: %s\n", errbuf);
	    exit(EXIT_FAILURE);
	}

	fflush(stdout);

	if (pcap_inject(pcapStatus, packet, size) == -1) {
	    pcap_perror(pcapStatus,0);
	    pcap_close(pcapStatus);
	    exit(1);
	}

	// Done
	printf("Packet was sent.\n\n");

}

/*
 * performCapture(unsigned char *filter, unsigned int *srcMac)
 *
 * Captures a packet meeting the filter conditions
 *
 */
int performCapture(unsigned char *filter, unsigned int *srcMac){

	pcap_t *handle;			/* Session handle */
	struct bpf_program fp;		/* The compiled filter */
	const u_char *packet;		/* The actual packet */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */

	/* Open the session */
	handle = pcap_open_live(deviceName, BUFSIZ, 0, 1500, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", deviceName, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		return(2);
	}

	/* Grab a packet */
	packet = pcap_next(handle, &header);

	/* Check if header is not 0 */
	if(header.len != 0){

		/* Print its length */
		printf("Captured packet meeting filter of [%d] bytes\n", header.len);

		/* Store and print source MAC for possible responses */
		int index = 0;
		for(int i = 6; i < 12; i++){
			srcMac[index] = packet[i];
			index++;
		}
		printf("Got packet from MAC: %02hhx:%02x:%02x:%02x:%02x:%02x !\n", srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5]);
	
		/* Print packet */
		printPacket(packet, header.len);

		/* Close the session */
		pcap_close(handle);

		/* Return 1 when finding a packet meeting conditions */
		return 1;
	} 
	
	/* Close the session */
	pcap_close(handle);
	
	/* Return 0 when not finding any packet meeting conditions */
	return 0;

}

int main(int argc, char *args[]) {

	char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
	char filter_exp_test[] = "ether[14:4] = 0x41424344";	/* Filter expression */
	char filter_exp_ack[] = "ether[14:4] = 0x44434241";	/* Filter expression */
	char testData[] = {'A', 'B', 'C', 'D'}; /* Test-link packet data */
	char ackData[] = {'D', 'C', 'B', 'A'}; /* Link-up packet data */
	unsigned int localMac[6]; /* Local MAC address of device */
	unsigned int dstMac[6]; /* Dst MAC address */
	unsigned char packet[64]; /* Packet  */
	int hexBlocks = 0; /* Hex blocks parsed from args  */

	/* Check number of args, if 4 run in link-test mode  */
	if (argc == 4){

		/* Print program mode */
		printf("Linkloop running in link-test mode...\n");
	
	    /* Device name is first arg  */
		deviceName = args[1];

		/* Check deviceName value */
		if (deviceName == NULL) {
    	    printf("%s\n", errbuf);
    	    exit(2);
    	}

		/* Scan local device MAC address from second arg  */
		hexBlocks = sscanf(args[2],"%x:%x:%x:%x:%x:%x", &(localMac[0]), &(localMac[1]), &(localMac[2]), &(localMac[3]), &(localMac[4]), &(localMac[5]));

		/* Check if MAC is valid */
		if(hexBlocks != 6){
			printf("Invalid MAC address!\n");
			exit(EXIT_FAILURE);
		}

		/* Scan dstMAC address (host to check) from third arg  */
		hexBlocks = sscanf(args[3],"%x:%x:%x:%x:%x:%x", &(dstMac[0]), &(dstMac[1]), &(dstMac[2]), &(dstMac[3]), &(dstMac[4]), &(dstMac[5]));

		/* Check if MAC is valid */
		if(hexBlocks != 6){
			printf("Invalid MAC address!\n");
			exit(EXIT_FAILURE);
		}
	
		/* Print packet send details */
		printf("Link-test packet will be sent to %02hhx:%02x:%02x:%02x:%02x:%02x using %s\n", dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5], deviceName);

		int count = 0;
		int pid;

		/* Fork program */
		if ((pid = fork()) < 0) { 
        	perror("fork"); 
        	exit(1); 
    	} 

		/* Child process will perform link-test packet sending until link-up packet or SIGINT*/
		if(pid == 0){

			/* Creates a link-test packet */
			createPacket(packet, testData, localMac, dstMac, sizeof(packet), sizeof(testData));

			/* Loop to send link-test packets, send and sleep for 10 seconds */
			while(1) {

				printf("Sending link-test packet...\n");
				sendPacket(packet, sizeof(packet));

				/* Increase link-test packet count sent so far */
				count++;
				printf("Test probes sent so far: %d \n", count);
				printf("Waiting 10 seconds before sending another test packet...\n");
				printf("To stop the program, press CTRL+C\n");
				printf("\n\n\n");

				sleep(10);

			}

		/* Parent process will perform capture filtering for link-up packets */
		}  else {

			while(1){

				printf("Looking for link-up packet...\n");
				fflush(stdout);

				/* If call to capture returns 1, link-up was found, hence host is up */
				if(performCapture(filter_exp_ack, dstMac)){

					printf("Host was reached after sending %d test packets, exiting... \n", count);
					printf("Host is up!\n");
					fflush(stdout);

					/* Terminate child process */
					kill(pid, 9);

					/* Exit program */
					exit(0);
				}

			}

		}

	/* If executed with 3 args, run in link-up mode */
	} else if (argc == 3) {

		/* Print program mode */
		printf("Linkloop running in linkup mode...\n");

		/* Device name is first arg  */
		deviceName = args[1];

		/* Check device name value  */
		if (deviceName ==  NULL) {
    	    printf("%s\n", errbuf);
    	    exit(2);
    	}

		/* Scan local device MAC address from second arg  */
		hexBlocks = sscanf(args[2],"%x:%x:%x:%x:%x:%x", &(localMac[0]), &(localMac[1]), &(localMac[2]), &(localMac[3]), &(localMac[4]), &(localMac[5]));

		/* Check if MAC is valid */
		if(hexBlocks != 6){
			printf("Invalid MAC address!.\n");
			exit(EXIT_FAILURE);
		}

		/* Perform capture looking for link-test packets */
		while(1){

			/* Perform capture looking for link-test packets */
			for(int i = 0; i < 6; i++){
				dstMac[i] = 0;
			}

			/* If call to capture returns 1, link-test was found, hence sending link-up packet */
			if(performCapture(filter_exp_test, dstMac)){

				printf("Received link-test, sending link-up packet!\n");

				/* Creates a link-up packet and sends it */
				createPacket(packet, ackData, localMac, dstMac, sizeof(packet), sizeof(ackData));
				sendPacket(packet, sizeof(packet));

			}

		}

	/* If number of args passed is not expected, print usage and exit */
	} else {

    	printf("%s <network interface> <interface MAC> <MAC address to test up> to run in link-test mode.\n", args[0]);
		printf("%s <network interface> <interface MAC> to run in link-up mode.\n", args[0]);
        exit(-1);

	}

}