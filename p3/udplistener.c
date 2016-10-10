/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#define BUFFER_SIZE     256

void error(const char *message){
    perror(message);
    exit(1);
}

int SocketFileDescriptor;

void SignalHandler(int param){
    close(SocketFileDescriptor);
    exit(0);
}

void DisplayMessage(char *data, int length){
    int Offset = 0;
    int Index;
    
    
    while(Offset < length){
       // printf("%04X ", Offset);
        for(Index = 0; Index < 16; Index++){
            if((Offset + Index) < length){
                printf("%02X ",data[Offset + Index]);
            }
            else{
                printf("   ");
            }
        }
        for(Index = 0; Index < 16; Index++){
            if((Offset + Index) < length){
                if((' ' <= data[Offset + Index])&&(data[Offset + Index] <= '~')){
                    printf("%c",data[Offset + Index]);
                }
                else{
                    printf(".");
                }
            }
            else{
                printf(" ");
            }
        }
        printf("\n");
        Offset += 16;
    }

}

int main(int argc, char *argv[]){
    int PortNumber;
    socklen_t ClientLength;
    char Buffer[BUFFER_SIZE];
    struct sockaddr_in ServerAddress, ClientAddress;
    int Result;
    time_t RawTime;
    struct tm TimeOut;
    
    if(2 > argc){
        fprintf(stderr,"ERROR, no port provided\n");
        exit(1);
    }
    
    PortNumber = atoi(argv[1]);
    if((1 > PortNumber)||(65535 < PortNumber)){
        fprintf(stderr,"Port %d is an invalid port number\n",PortNumber);
        exit(0);
    }
    // Create UDP/IP socket
    SocketFileDescriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(0 > SocketFileDescriptor){
        error("ERROR opening socket");
    }
    signal(SIGTERM, SignalHandler);
    signal(SIGINT, SignalHandler);
    signal(SIGUSR1, SignalHandler);
    
    
    // Setup ServerAddress data structure
    bzero((char *) &ServerAddress, sizeof(ServerAddress));
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = INADDR_ANY;
    ServerAddress.sin_port = htons(PortNumber);
    // Binding socket to port
    if(0 > bind(SocketFileDescriptor, (struct sockaddr *)&ServerAddress, sizeof(ServerAddress))){ 
        error("ERROR on binding");
    }

    while(1){
        ClientLength = sizeof(ClientAddress);
        bzero(Buffer, BUFFER_SIZE);
        // Receive message from client
        Result = recvfrom(SocketFileDescriptor, Buffer, BUFFER_SIZE, 0, (struct sockaddr *)&ClientAddress, &ClientLength);
        if(0 > Result){
            error("ERROR receive from client");
        }
        
        time ( &RawTime );
        localtime_r(&RawTime, &TimeOut);
        
        printf("Received Message %d bytes @ %04d/%02d/%02d %02d:%02d:%02d\n", Result, TimeOut.tm_year+1900, TimeOut.tm_mon+1, TimeOut.tm_mday, TimeOut.tm_hour, TimeOut.tm_min, TimeOut.tm_sec);
        DisplayMessage(Buffer, Result);
        fflush(stdout);
    }
    close(SocketFileDescriptor);
    return 0; 
}
