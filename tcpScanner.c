#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <semaphore.h>
#include <pthread.h>



#define IP_STRING_LENGTH 15 //max length of ipv4

//status codes
#define PORT_STATUS_CLOSED 0
#define PORT_STATUS_OPEN 1
#define PORT_STATUS_CLOSED_STR "closed"
#define PORT_STATUS_OPEN_STR "open"

//max scanning thrad count
#define MAX_THREADS 50


typedef struct scan_t{
	int socket;
	struct in_addr ip;
	int portsLength;
	short *ports; 
	sem_t *sem;
}scan_t;

//connect to master
int ConnectToServer(char* server, char* port){
	int sock; //new socket
	struct in_addr ip;
	struct sockaddr_in address;
	socklen_t addrlen = sizeof(struct sockaddr);
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock==-1){
		perror("socket");
        return -1;
    }
    inet_pton(AF_INET, server, &ip);
    address.sin_family = AF_INET;
    address.sin_port = htons(atoi(port));
    address.sin_addr = ip;
    //connect to server, on error print it and return
    if(connect(sock, (struct sockaddr*)&address, addrlen)==-1){
    	printf("can’t connect to %s on tcp %s \n", server, port);
        return -1;
    }
    printf("connected to %s on tcp %s \n", server, port);
    return sock; //return filedescriptor of this connection
}
//returns length of range
int GetIpsLengthFromRange(struct in_addr start, struct in_addr end){
	in_addr_t ip1 = ntohl(start.s_addr);
	in_addr_t ip2 = ntohl(end.s_addr);
	return (int)(ip2 - ip1)+1;
}
//increments and returns ip
struct in_addr GetNextIp(struct in_addr cur){
	in_addr_t next = htonl(ntohl(cur.s_addr)+1);
	struct in_addr result;
	result.s_addr = next;

	fflush(stdout);
	return result;
}
//gets array of ips from range
struct in_addr *GetIps(struct in_addr start, struct in_addr end, int *ipsLength){
	int numIps = GetIpsLengthFromRange(start, end);
	*ipsLength = numIps;

	
	struct in_addr *ips = malloc(sizeof(struct in_addr)*numIps);
	int i;
	struct in_addr cur = start;
	for(i=0; i<numIps; i++){
		ips[i] = cur;
		cur = GetNextIp(cur);
	}
	return ips;

}

//recieves and processes range from socket
struct in_addr *GetIpRange(int socket, int *ipsLength){

	struct in_addr start;

	if(recv(socket, &start, sizeof(struct in_addr), 0) == -1){
		perror("recieving");
		exit(-1);
	}

	struct in_addr end;

	if(recv(socket, &end, sizeof(struct in_addr), 0) == -1){
		perror("recieving");
		exit(-1);
	}
	struct in_addr *ips = GetIps(start, end, ipsLength);
	return ips;
}
//recieve ports
short* GetPorts(int socket, int portsLength){
	int i;
	short *ports = malloc(sizeof(short)*portsLength);
	int num;
		if((num=recv(socket, ports, sizeof(short)*portsLength, 0)) == -1){
			perror("recieving ports");
			exit(-1);
		}

	return ports;
}
//check if given port is open on given ip
int isOpen(struct in_addr ip, short port){
	// int i;
	// for(i=0; i<100000000;i++);
	int sock; //new socket
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(struct sockaddr);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock==-1){
        perror("socket");
        return 0;
    }
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr = ip;

    //connect to server
    if(connect(sock, (struct sockaddr*)&address, addrlen)==-1){
    	close(sock);
        return 0;
    }
    close(sock);
    return 1;
}
//scans ip for open ports
void * ScanIp(void* data){
	struct scan_t *scan = (struct scan_t*)data;
	char ipstr[IP_STRING_LENGTH+1];
	bzero(ipstr, IP_STRING_LENGTH);
	int i;
	char* statusStr;
	int *status = malloc(sizeof(int)*scan->portsLength);
	for(i=0; i<scan->portsLength; i++){
		if(isOpen(scan->ip, scan->ports[i])){
			statusStr = strdup(PORT_STATUS_OPEN_STR);
			status[i] = PORT_STATUS_OPEN;
		}else{
			statusStr = strdup(PORT_STATUS_CLOSED_STR);
			status[i] = PORT_STATUS_CLOSED;
		}

		printf("Port %d is %s on server %s\n", scan->ports[i], statusStr, inet_ntop(AF_INET, &(scan->ip), ipstr, IP_STRING_LENGTH));
		free(statusStr);
	}
	if(send(scan->socket, &scan->ip, sizeof(struct in_addr),0)!=sizeof(struct in_addr)){
			perror("Sending");
			exit(-1);
		}
	if(send(scan->socket, status, sizeof(int)*scan->portsLength, 0) != sizeof(int)*scan->portsLength){
		perror("Sending");
		exit(-1);
	}
	sem_post(scan->sem);

}
//create and start thread for scanning ips
int doProcessing(int socket, int ipsLength, struct in_addr *ips, int portsLength, short *ports){
	
	pthread_t *threads = malloc(sizeof(pthread_t)*ipsLength);
	struct scan_t *data = malloc(sizeof(struct scan_t)*ipsLength);
	sem_t *semaphore = malloc(sizeof(sem_t));
	sem_init(semaphore,0, MAX_THREADS);
	int i; 
	for(i = 0; i < ipsLength; i++){
		data[i].socket = socket;
		data[i].ip = ips[i];
		data[i].portsLength = portsLength;
		data[i].ports = ports;
		data[i].sem = semaphore;
		sem_wait(data[i].sem);
		pthread_create(&threads[i], NULL, ScanIp, (void*)&data[i]);
	}
	for(i=0; i < ipsLength; i++)
		pthread_join(threads[i], NULL);
	

	printf("Working Finished\n");

	free(data);
	free(threads);
}	
//get number of ports
int GetLength(int socket){
	int length;
	if(recv(socket, &length, sizeof(int), 0) == -1){
		perror("recieving numPorts");
		exit(-1);
	}
	length = ntohl(length);

	return length;
}

void *startTcpScanner(int socket){
	while(1){
		int ipsLength;
		struct in_addr *ips = GetIpRange(socket, &ipsLength);

		if(ips==NULL){
			printf("Working Finished\n");
			fflush(stdout);
			break;
		}
		int portsLength = GetLength(socket);
		short *ports = GetPorts(socket, portsLength);
		doProcessing(socket, ipsLength, ips, portsLength, ports);
		free(ips);
		free(ports);
	}
}

int main(int argc, char* argv[]){
	if(argc == 3){
		int socket = ConnectToServer(argv[1], argv[2]);
		startTcpScanner(socket);
	}else{
		exit(1);
	}
	return 0;
}