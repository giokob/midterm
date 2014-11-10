#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <semaphore.h>   


#define PORT 44543 //Port on witch we will listen
#define IP "0.0.0.0"


#define IP_STRING_LENGTH 15 //max length of ipv4

//status constants
#define IP_STATUS_AVAILABLE 0
#define IP_STATUS_WAITING 1
#define IP_STATUS_SCANNED 2

// bl bla bal
#define MAX_RANGE_LENGTH 30 //maqsimum ramxela diapazoni gavugzavnot skaners

#define ZERO_CHAR '0'

//status constants
#define PORT_STATUS_CLOSED 0
#define PORT_STATUS_OPEN 1
//string representation of same constants
#define PORT_STATUS_CLOSED_STR "closed"
#define PORT_STATUS_OPEN_STR "open"

//ip range
typedef struct range{
	struct in_addr start;
	struct in_addr end;
}range;

typedef struct scanData{
	int numIps; //number of ips
	struct in_addr* ips; //array of ips that are needed to send
	char *statuses; //array of status codes for each ip
	int scannedIps; //number of scanned ips
	sem_t *dataSem;	//semaphore for locking stucture
}scanData;

typedef struct threadData{
 	struct scanData *scanData;
 	int descriptor; //socket descriptor
 	int numPorts; //number of ports to scan
 	short *ports; //array of ports
 	struct in_addr threadAddress; //address of the scanner
}threadData;
//returns nex available range with maximum length of MAX_RANGE_LENGTH
struct range *GetNextRange(struct scanData *scanData){
	struct range *range = NULL;
	int i;
	sem_wait(scanData->dataSem);
	for(i = MAX_RANGE_LENGTH; i>0; i--){
		char *str = malloc(i);
		memset(str, ZERO_CHAR + IP_STATUS_AVAILABLE, i);
		char* result = strstr(scanData->statuses, str);
		free(str);
		if(result != NULL){
			memset(result, ZERO_CHAR + IP_STATUS_WAITING, i+1);
			int start = result - scanData->statuses;
			int end = start+i;
			range = malloc(sizeof(range));		
			range->start = scanData->ips[start];
			range->end = scanData->ips[end];
			break;
		}
	}
	sem_post(scanData->dataSem);
	return range;
}

//returns length of range
int GetIpsLengthFromRange(struct in_addr start, struct in_addr end){
	in_addr_t ip1 = ntohl(start.s_addr);
	in_addr_t ip2 = ntohl(end.s_addr);
	return (int)(ip2 - ip1)+1;
}

//build data needed for scanning
struct scanData *GetScanData(struct range range){
	struct scanData *data = malloc(sizeof(struct scanData));

	//get number of ips
	data->numIps = GetIpsLengthFromRange(range.start, range.end);
	
	printf("NumIps:%d\n", data->numIps);
	fflush(stdout);
	//initialize status codes
	data->statuses = malloc(data->numIps+1);
	bzero(data->statuses, data->numIps+1);
	//initialize array for ips
	data->ips = malloc(sizeof(struct in_addr)*data->numIps);
	

	data->scannedIps = 0;
	data->dataSem = malloc(sizeof(sem_t));
	sem_init(data->dataSem, 0, 1);
	memset(data->statuses, ZERO_CHAR+IP_STATUS_AVAILABLE, data->numIps);
	
	int i;
	for(i=0; i<data->numIps; i++){
		in_addr_t tmp = ntohl(range.start.s_addr)+i;
		struct in_addr tmpaddr;
		tmpaddr.s_addr = htonl(tmp);
		data->ips[i] = tmpaddr;
	}

	return data;
}


//establish connection
int StartServer(struct sockaddr_in address, socklen_t addrlen){
	printf("Establishing server connection...\n");   
    int sock;//new socket        
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock==-1){//in case of error print error and return
        perror("socket");
        exit(-1);
    }
    printf("binding port...\n");
    if(bind(sock,(struct sockaddr*)&address,addrlen)==-1){//bind to the port in case of error print error and return
        perror("binding");
        exit(-1);
    }
    printf("Starting listening...\n");
    if(listen(sock,0)==-1){//start listening to the binded port in case of error print error and return
        perror("listening");
        exit(-1);
    }
    printf("Waiting for connection...\n");
    return sock;
}
//send range to scanner
void *SendRange(int descriptor, struct range *range){
	if(send(descriptor, &range->start, sizeof(struct in_addr), 0)!=sizeof(struct in_addr)){
		perror("sending start of range");
		exit(-1);
	}

	if(send(descriptor, &range->end, sizeof(struct in_addr), 0) !=sizeof(struct in_addr)){
		perror("sending end of range");
		exit(-1);
	}
}
//send ports to scanner
void *SendPorts(int descriptor, int numPorts, short *ports){
	int nnumPorts = htonl(numPorts);
	if(send(descriptor, &nnumPorts, sizeof(int),0) != sizeof(int)){
		perror("sending ports length");
		exit(-1);
	}


	if(send(descriptor, ports, numPorts*sizeof(short), 0) != numPorts*sizeof(short)){
		perror("sending ports");
		exit(-1);
	}
}
//read result from scanner for every ip and print
void *PrintResult(struct in_addr ip, char* threadAddress, int descriptor, int numPorts, short *ports){
	
	int *statuses = malloc(sizeof(int)*numPorts);
	if(read(descriptor, statuses, sizeof(int)*numPorts, 0)==-1){
		perror("reading ports");
		return NULL;
	}
	char *temp = malloc(IP_STRING_LENGTH);
	printf("(%s): %s port ", threadAddress, inet_ntop(AF_INET,&ip,temp,IP_STRING_LENGTH));
	free(temp);
	char * statusStr;
	int i;
	for(i=0; i<numPorts; i++){
		if(statuses[i] == PORT_STATUS_OPEN){
			statusStr = strdup(PORT_STATUS_OPEN_STR);
		}else{
			statusStr = strdup(PORT_STATUS_CLOSED_STR);
		}
		printf("%d %s", ports[i],statusStr);
		if(i!=numPorts-1)
			printf(",");
		else
			printf("\n");
	}
	int *dummy;
	return dummy;
}
//compate method for two ips
int cmpIp(const void *one, const void *two){
	return ((struct in_addr*)one)->s_addr - ((struct in_addr*)two)->s_addr;
}

//marks ip as read and increments scannedips
void *RecordIp(struct in_addr ip, scanData *scanData){

	sem_wait(scanData->dataSem);
	int index = (struct in_addr*)bsearch(&ip, scanData->ips, (size_t)scanData->numIps, sizeof(struct in_addr), cmpIp) - scanData->ips;

	if(index>=0)
		scanData->statuses[index] = IP_STATUS_SCANNED;
	
	scanData->scannedIps++;
	
	sem_post(scanData->dataSem);
}
//if connection broke set status of not scanned ips to available
void *rollBack(struct in_addr start, int length, scanData *scanData){
	int index = (struct in_addr*)bsearch(&start, scanData->ips, (size_t)scanData->numIps, sizeof(struct in_addr), cmpIp) - scanData->ips;
	int i;
	for(i=0; i<length; i++)
		if(scanData->statuses[i] == IP_STATUS_WAITING)
			scanData->statuses[i] = IP_STATUS_AVAILABLE;
}
//communication function with scanner. used in thread
void *SendData(void *data){
	//loop until there are ip's available
	while(1){
		struct threadData *threadData = (struct threadData*)data; 
		struct range *range = GetNextRange(threadData->scanData);
		if(range == NULL){
			break;
		}	
		int numIps = GetIpsLengthFromRange(range->start, range->end);

		char* address = malloc(IP_STRING_LENGTH+1);
		inet_ntop(AF_INET, &threadData->threadAddress, address, IP_STRING_LENGTH+1);
		SendRange(threadData->descriptor, range);
		
		SendPorts(threadData->descriptor, threadData->numPorts, threadData->ports);
		
		int scannedIps = 0;
		//wait for scanners responses
		while(1){
			sem_wait(threadData->scanData->dataSem);
			if(scannedIps == numIps){
				sem_post(threadData->scanData->dataSem);
				break;
			}
			sem_post(threadData->scanData->dataSem);
			//get scanned ip
			struct in_addr ip;
			if(read(threadData->descriptor, &ip, sizeof(struct in_addr), 0)==-1){
				perror("reading");
				return NULL;
			}
			
			//print results about ports
			if(PrintResult(ip, address, threadData->descriptor, threadData->numPorts, threadData->ports)==NULL){
			 	printf("Connection to thread [%s] lost", address);
			 	rollBack(range->start, numIps, threadData->scanData);
			 	break;
			}

			RecordIp(ip, threadData->scanData);


			scannedIps++;

		}
		free(address);	
	}	
	free(data);
}
//returns scanners ip address
struct in_addr GetPeerAddress(int descriptor){
	struct sockaddr_in address;
	socklen_t addrlen = sizeof(struct sockaddr);
	if(getpeername(descriptor, (struct sockaddr*)&address, &addrlen)==-1){
		perror("getting peer address");
		exit(-1);
	}
	return address.sin_addr;
}
//creates and starts thread for scanner
void *startProcessing(int descriptor, struct in_addr peerAddress,  scanData *data, int numPorts, short *ports){
	pthread_t thread;
	struct threadData *threadData = malloc(sizeof(struct threadData));

	threadData->scanData = data;
	threadData->descriptor = descriptor;
	threadData->numPorts = numPorts;
	threadData->ports = ports;
	threadData->threadAddress = peerAddress;
	pthread_create(&thread, NULL, SendData, (void*)threadData);
}


//initialize starting parameters and wait for scanner to connect
void *StartScanning(struct range range, int numPorts, short *ports){
	printf("getting scan data\n");
	fflush(stdout);

	struct scanData *data = GetScanData(range);
	
	printf("Scan data got\n");
	fflush(stdout);

	struct in_addr ip;
	struct sockaddr_in address;
	socklen_t addrlen = sizeof(struct sockaddr);
	inet_pton(AF_INET, IP, &ip);
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr = ip;
	int socket = StartServer(address, addrlen);	

	printf("socket is: %d\n", socket);
	fflush(stdout);
	

	while(1){

		sem_wait(data->dataSem);
		if(data->scannedIps == data->numIps){
			printf("scannedIps == numIps\n");
			fflush(stdout);
			sem_post(data->dataSem);			
			break;
		}
		sem_post(data->dataSem);

		int descriptor = accept(socket, (struct sockaddr*)&address, &addrlen);
    	if(descriptor==-1){
    	    perror("accepting");
	    	continue;
	    }
	    printf("Connected!\n");
	    struct in_addr peerAddress = GetPeerAddress(descriptor);
    	startProcessing(descriptor, peerAddress, data, numPorts, ports);
	}
	//free(data);
	close(socket);
	printf("Finished Scanning!");
	fflush(stdout);
}

//get ports from string
short* GetPorts(int numPorts, char* ports[]){
	short *res = malloc(sizeof(short)*numPorts);
	int i;
	for(i = 0; i<numPorts; i++){
		res[i] = atoi(ports[i]);
	}
	return res;
}

//get range from ip and subnet mask
struct range GetRange(struct in_addr ip, struct in_addr subnet){
	int hostBinary = ntohl(ip.s_addr);
	int subnetBinary = ntohl(subnet.s_addr);

	int network = hostBinary&subnetBinary;

	int reverseSubnet = ~subnetBinary;

	int networkMax = network^reverseSubnet;

	struct range range;

	struct in_addr start;
	struct in_addr end;

	start.s_addr = htonl(network);
	end.s_addr = htonl(networkMax);

	range.start = start;

	range.end = end;

	return range;
}




int main(int argc, char* argv[]){
	if(argc>3){
		struct in_addr ip;
		struct in_addr subnet;

		inet_pton(AF_INET, argv[1], &ip);
		inet_pton(AF_INET, argv[2], &subnet);
		printf("Getting Ports!\n");
		fflush(stdout);
		short* ports = GetPorts(argc-3, &argv[3]);
		printf("Ports got!\n");
		fflush(stdout);

		printf("Getting range!\n");
		fflush(stdout);
		struct range range = GetRange(ip, subnet);


		StartScanning(range, argc-3, ports);

		free(ports);
	}else{
		exit(-1);
	}
	return 0;
}
