all: tcpScanner master

master: master.c
	gcc master.c -lpthread -o master 

tcpScanner: tcpScanner.c
	gcc tcpScanner.c -lpthread -o tcpScanner 
