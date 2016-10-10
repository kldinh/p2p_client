//Kevin Dinh
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <iostream> 
#include <vector> 
#include <sys/poll.h>
#include <termios.h>
#include <ctype.h>


using namespace std;

#define BUFFER_SIZE     1024

void talk();
void check_tcp();
void request_user_list();
void check_udp();
void remove_from_list(char* temp_username, char* temp_hostname);


char udp_disc_buffer[BUFFER_SIZE]; //UDP discovery message
char udp_close_buffer[BUFFER_SIZE]; //UDP closing message 
char udp_reply_buffer[BUFFER_SIZE]; //UDP reply message

char recv_buffer[BUFFER_SIZE]; // incoming message

char tcp_request_buffer[BUFFER_SIZE]; //TCP establish communicate message
char tcp_data_message_buffer[BUFFER_SIZE];//send text message
char tcp_dis_buffer[BUFFER_SIZE]; //disconnect message
char tcp_request_list_buffer[BUFFER_SIZE];
char tcp_recieve_buffer[BUFFER_SIZE];

char tcp_poll_buffer[BUFFER_SIZE];

int udp_portnumber_global;
int tcp_portnumber_global;
string my_username;
char my_hostname[1024];

int user_leng; //username length
int host_length; //hostname length


struct pollfd ufds[1];
int poll_value;
int timeout = 5000;

struct pollfd udp[1];
int udp_poll_value;
int udp_timeout = 1;

struct pollfd tcp[1];
int tcp_poll_value;
int tcp_timeout = 4000;



//for noncanmode
string backspace = "\b \b";
string bell = "\a";
string command_string;


//own TCP
int tcp_own_SocketFileDescriptor, tcp_own_NewSocketFileDescriptor;
socklen_t tcp_own_ClientLength;
struct sockaddr_in tcp_own_ServerAddress, tcp_own_ClientAddress;




//UDP Unicast
struct sockaddr_in udp_direct_ServerAddress;
struct hostent * udp_direct_Server;



//UDP Broadcaststuff
int udp_SocketFileDescriptor, udp_portnumber, Result, BroadcastEnable, udp_normal_SocketFileDescriptor;
struct sockaddr_in udp_bc_ServerAddress, udp_ClientAddress, udp_normal_ServerAddress;
socklen_t udp_ClientLength;

//TCP Stuff
int tcp_SocketFileDescriptor, tcp_NewSocketFileDescriptor, tcp_portnumber;
socklen_t tcp_ClientLength;
char Buffer[BUFFER_SIZE];
struct sockaddr_in tcp_ServerAddress, tcp_ClientAddress;
struct hostent *tcp_Server;



//struct for neighbors
struct client{

    char client_username[256];
    char client_hostname[256];
    char client_pc_name[256];
    int client_udp_port;
    int client_tcp_port;

    client( char* username, char* hostname, const char* pcname, int udp, int tcp )
    {
        strcpy(client_username,username);
        strcpy(client_hostname, hostname);
        strcpy(client_pc_name, pcname);
        client_udp_port = udp;
        client_tcp_port = tcp;
    }

};


struct tcp_clients
{
    int user_id;
    char* client_username;
    int tcp_port;

    tcp_clients(int user_id2, char* client_username2, int tcp_port2)
    {   
       user_id = user_id;
       client_username = client_username2;
       tcp_port = tcp_port2;

    }


};

vector<client*> friends_list;

vector<tcp_clients*> tcp_friends;

void error(const char *message){
    perror(message);
    exit(0);
}


void SignalHandler(int param){
    close(udp_SocketFileDescriptor);
    exit(0);
}

void send_udp_discovery()
{   
    //set up P2P signature and make discovery type
    udp_disc_buffer[0] = 'P'; udp_disc_buffer[1] = '2'; udp_disc_buffer[2] = 'P'; udp_disc_buffer[3] = 'I';
    udp_disc_buffer[4] =  0; udp_disc_buffer[5] = 1;

    //set UDP port
    udp_disc_buffer[6] = htons(udp_portnumber_global) & 0xFF; 
    udp_disc_buffer[7] = htons(udp_portnumber_global) >> 8; 

    //set TCP port
    udp_disc_buffer[8] = htons(tcp_portnumber_global) & 0xFF; 
    udp_disc_buffer[9] = htons(tcp_portnumber_global) >> 8; 


    int user_leng = my_username.length(); //username length
    int host_length = strlen(my_hostname); //hostname length

    char username_buf[user_leng]; //converting my_username from string to a char[]
    strcpy(username_buf, my_username.c_str());

    //putting in hostname
    for(int i = 0; i < host_length+1; i++)
    {
        if(i == host_length)
            udp_disc_buffer[10+i] = '\0';
        else
            udp_disc_buffer[10+i] = my_hostname[i]; 
    }

    //putting in username
     for(int i = 0; i < user_leng+1; i++)
    {   
        if(i == user_leng)
            udp_disc_buffer[10+i+host_length + 1] = '\0';
        else
            udp_disc_buffer[10+i+host_length + 1] = username_buf[i];
    }


    cout << "Sending UDP Broadcast" << endl;
   int Result = sendto(udp_SocketFileDescriptor, udp_disc_buffer, (10+2+user_leng+host_length), 0, (struct sockaddr *)&udp_bc_ServerAddress, sizeof(udp_bc_ServerAddress));
        if(0 > Result){ 
            error("ERROR sending discovery boardcast\n");
        }

}//send_udp_discovery()


void send_udp_reply(const char* pc_name)
{


    //set up P2P signature and make discovery type
    udp_reply_buffer[0] = 'P'; udp_reply_buffer[1] = '2'; udp_reply_buffer[2] = 'P'; udp_reply_buffer[3] = 'I';
    udp_reply_buffer[4] =  0; udp_reply_buffer[5] = 2;

    //set UDP port
    udp_reply_buffer[6] = htons(udp_portnumber_global) & 0xFF; 
    udp_reply_buffer[7] = htons(udp_portnumber_global) >> 8; 

    //set TCP port
    udp_reply_buffer[8] = htons(tcp_portnumber_global) & 0xFF; 
    udp_reply_buffer[9] = htons(tcp_portnumber_global) >> 8; 


    char username_buf[user_leng]; //converting my_username from string to a char[]
    strcpy(username_buf, my_username.c_str());


    //putting in hostname
    for(int i = 0; i < host_length+1; i++)
    {
        if(i == host_length)
            udp_reply_buffer[10+i] = '\0';
        else
            udp_reply_buffer[10+i] = my_hostname[i]; 
    }

    //putting in username
     for(int i = 0; i < user_leng+1; i++)
    {   
        if(i == user_leng)
            udp_reply_buffer[10+i+host_length + 1] = '\0';
        else
            udp_reply_buffer[10+i+host_length + 1] = username_buf[i];
    }


     udp_direct_Server = gethostbyname(pc_name);
    if(NULL == udp_direct_Server){
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }


    bzero((char *) & udp_direct_ServerAddress, sizeof(udp_direct_ServerAddress));
    udp_direct_ServerAddress.sin_family = AF_INET;
    bcopy((char *)udp_direct_Server->h_addr, (char *)&udp_direct_ServerAddress.sin_addr.s_addr, udp_direct_Server->h_length);
    udp_direct_ServerAddress.sin_port = htons(udp_portnumber_global);



    cout << "Sending Reply" << endl;
   int Result = sendto(udp_SocketFileDescriptor, udp_reply_buffer, (10+2+user_leng+host_length), 0, (struct sockaddr *)&udp_direct_ServerAddress, sizeof(udp_direct_ServerAddress));
    //printf("Result = %d\n", Result );
        if(0 > Result){ 
            error("ERROR sending closing boardcast\n");
        }




}

void print_friends()
{
    cout << endl << "Discovered " << friends_list.size() << " Users: " << endl;

    for(unsigned int i = 0; i < friends_list.size(); i++)
    {
        cout << "User " << i << " " << friends_list[i]->client_username << "@" << friends_list[i]->client_hostname << " on UDP " << friends_list[i]->client_udp_port << ", TCP " << friends_list[i]->client_tcp_port << endl;
        //cout <<"PC name = " << friends_list[i]->client_pc_name << endl;
    }



}


void send_udp_closing()
{
    //set up P2P signature and make discovery type
    udp_close_buffer[0] = 'P'; udp_close_buffer[1] = '2'; udp_close_buffer[2] = 'P'; udp_close_buffer[3] = 'I';
    udp_close_buffer[4] =  0; udp_close_buffer[5] = 3;

    //set UDP port
    udp_close_buffer[6] = htons(udp_portnumber_global) & 0xFF; 
    udp_close_buffer[7] = htons(udp_portnumber_global) >> 8; 

    //set TCP port
    udp_close_buffer[8] = htons(tcp_portnumber_global) & 0xFF; 
    udp_close_buffer[9] = htons(tcp_portnumber_global) >> 8; 


    char username_buf[user_leng]; //converting my_username from string to a char[]
    strcpy(username_buf, my_username.c_str());


    //putting in hostname
    for(int i = 0; i < host_length+1; i++)
    {
        if(i == host_length)
            udp_close_buffer[10+i] = '\0';
        else
            udp_close_buffer[10+i] = my_hostname[i]; 
    }

    //putting in username
     for(int i = 0; i < user_leng+1; i++)
    {   
        if(i == user_leng)
            udp_close_buffer[10+i+host_length + 1] = '\0';
        else
            udp_close_buffer[10+i+host_length + 1] = username_buf[i];
    }


    cout << endl << "Sending Closing Boardcast" << endl;
   int Result = sendto(udp_SocketFileDescriptor, udp_close_buffer, (10+2+user_leng+host_length), 0, (struct sockaddr *)&udp_bc_ServerAddress, sizeof(udp_bc_ServerAddress));
    //printf("Result = %d\n", Result );
        if(0 > Result){ 
            error("ERROR sending closing boardcast\n");
        }

}//send_udp_closing()

void print_start_info()
{
    cout << "Username = " <<  my_username << endl;
    cout << "Hostname = " << my_hostname << endl;
    cout << "UDP Port = " << udp_portnumber_global << endl;
    cout << "TCP Port = " << tcp_portnumber_global << endl;

}//print_start_info()


void listen_udp_reply()
{

    while(1)
    {

        poll_value = poll(ufds, 1, timeout);

        int self_discover_flag = 0;
        //int found_someone = 0;

        if(poll_value == 0)
        {   
            if(timeout == 5000)
            {   
                timeout = 10000;
                cout << "Cannot find anyone. Resending Broadcast. Timeout = 10s" << endl;
                send_udp_discovery();
            }
            else if(timeout == 10000)
            {   
                timeout = 20000;
                cout << "Cannot find anyone. Resending Broadcast. Timeout = 20s" << endl;
                send_udp_discovery();
            }
            else if(timeout == 20000)
            {
                timeout = 40000;
                cout << "Cannot find anyone. Resending Broadcast. Timeout = 40s" << endl;
                send_udp_discovery();
            }   
            else if(timeout == 40000)
            {
                timeout = 60000;
                cout << "Cannot find anyone. Resending Boardcast. Timeout = 60s" << endl;
                send_udp_discovery();
            }

        }

        if(ufds[0].revents & POLLIN)
        {
            //cout << "got into reciving" << endl;
            Result = recvfrom(udp_normal_SocketFileDescriptor, recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&udp_ClientAddress, &udp_ClientLength);
            if(0 > Result)
                error("ERROR receive from client");

             //testing if recived own broadcast
            for(int i = 0; i < host_length + 1 + user_leng + 1; i++)
            {
                if(recv_buffer[10+i] == udp_disc_buffer[10+i])
                    self_discover_flag = 1;
                else
                    {
                       // cout << "not the same" << endl;
                        self_discover_flag = 0;
                        break;
                    }

                if(i == host_length && self_discover_flag == 1 )
                    {
                        cout << "Recevied Self Discover" << endl;
                        //self_discover_flag = 0;
                    }     
            }//testing to see if recived own broadcast


            if(self_discover_flag == 0) //if did not recieve own broadcast
            {

                int index1 = 0; //to find first \0
                int index2 = 0; //to find second \0
      
                    //parsing for '/0'
                    for(int i = 0; i<1024; i++)
                    {
                        if(recv_buffer[10+i] == '\0' && index1 == 0)
                            index1 = i;
                        else if(recv_buffer[10+i] == '\0' && index1 != 0)
                        {
                            index2 = i;
                            break;
                        }

                    }//for parsing '/0'

                char temp_hostname[index1+1]; //
                char temp_username[index2-index1];

                string pc_name;

                for(int i = 0; i < index1+1; i++)
                    temp_hostname[i] = recv_buffer[10+i]; //gets hostname with \0

                for(int k = 0; k < index2-index1; k++)
                    temp_username[k] = recv_buffer[index1+k+10+1]; //gets user name with \0

                int temp_udpport = ntohs(*(uint16_t *)(recv_buffer+ 6)); //to get UDP port number to int
                int temp_tcpport = ntohs(*(uint16_t *)(recv_buffer+ 8)); // to get TCP port number to int

                 for(int i = 0; i < index1+1; i++) //to parse for pc number (Server)
                {
                    char c = temp_hostname[i];

                    if(c == '.')
                      break;
                    else
                     pc_name += c;
                }    

                const char* temp_pc_name = pc_name.c_str();

            
                if(recv_buffer[5] == 1) //Recived a Discover Message
                    {
                        cout << "Recevied Discover from " << temp_username << "@" << temp_hostname << " on UDP " << temp_udpport << ", TCP " << temp_tcpport << endl;
                        send_udp_reply(temp_pc_name);
                        client * peer = new client( temp_username, temp_hostname, temp_pc_name, temp_udpport, temp_tcpport);
                        friends_list.push_back(peer);
                        print_friends();
                        talk();
                    }
                else if(recv_buffer[5] == 2)//Recived a Reply Message 
                    {
                        cout << "Recevied Reply from " << temp_username << "@" << temp_hostname << " on UDP " << temp_udpport << ", TCP " << temp_tcpport << endl;
                        client * peer = new client( temp_username, temp_hostname, temp_pc_name, temp_udpport, temp_tcpport);
                        friends_list.push_back(peer);
                        print_friends();
                        talk();
                    }
                else if(recv_buffer[5] == 3)
                    {
                         cout << "Recevied Closing from " << temp_username << "@" << temp_hostname << " on UDP " << temp_udpport << ", TCP " << temp_tcpport << endl;
                    }

            } // if found someone and not own broadcast     
     

        }//if(ufds[0].revents & POLLIN)
    }//while(1)


}//listen_to_udpreply()



void send_tcp_request() //request establish communication 
{
   cout << "Sending Establish Communication Message..." << endl;
    tcp_request_buffer[0] = 'P'; tcp_request_buffer[1] = '2'; tcp_request_buffer[2] = 'P'; tcp_request_buffer[3] = 'I';
    tcp_request_buffer[4] =  0; tcp_request_buffer[5] = 4;

     for(int i = 0; i < user_leng+1; i++)
    {
        if(i == user_leng)
            tcp_request_buffer[6+i] = '\0';
        else
            tcp_request_buffer[6+i] = my_username[i]; 
    }


     Result = write(tcp_SocketFileDescriptor, tcp_request_buffer, (4+2+user_leng+1) );
    if(0 > Result){ 
        error("ERROR writing to socket");
    }

}

void ResetCanonicalMode(int fd, struct termios *savedattributes){
    tcsetattr(fd, TCSANOW, savedattributes);
}


void SetNonCanonicalMode(int fd, struct termios *savedattributes){
    struct termios TermAttributes;
    //char *name;
    
    // Make sure stdin is a terminal. 
    if(!isatty(fd)){
        fprintf (stderr, "Not a terminal.\n");
        exit(0);
    }
    
    // Save the terminal attributes so we can restore them later. 
    tcgetattr(fd, savedattributes);
    
    // Set the funny terminal modes. 
    tcgetattr (fd, &TermAttributes);
    TermAttributes.c_lflag &= ~(ICANON | ECHO); // Clear ICANON and ECHO. 
    TermAttributes.c_cc[VMIN] = 1;
    TermAttributes.c_cc[VTIME] = 0;
    tcsetattr(fd, TCSAFLUSH, &TermAttributes);
}



void send_message()
{
    struct termios SavedTermAttributes;
    char RXChar;

    cout << endl << "Enter a Message: " << endl;
    char send_message[BUFFER_SIZE];

    bzero(send_message, BUFFER_SIZE);

    send_message[0] = 'P';  send_message[1] = '2'; send_message[2] = 'P';  send_message[3] = 'I';
    send_message[4] = 0; send_message[5] = 9;

    string message;
    const char *message_buffer;
    int message_length;

    SetNonCanonicalMode(STDIN_FILENO, &SavedTermAttributes);

    while(1)
    {
        read(STDIN_FILENO, &RXChar, 1);
        
        if(isprint(RXChar) && RXChar != 0x5B && RXChar != 0x41 && RXChar != 0x42) //normal char
            {
                write(STDOUT_FILENO, &RXChar, 1);  
                message = message + RXChar;
            }

        if(RXChar == 0x08 || RXChar == 0x7F)//backspace
            {
                if(message.size()> 0)
                 {       
                    write(STDOUT_FILENO, backspace.c_str(), backspace.length());
                    message.erase(message.size() - 1);
                }
                else
                    write(STDOUT_FILENO, bell.c_str(), bell.length());
            }

        if(RXChar == 0x0A) //pressed enter
            break;


    }



    message_length = message.size();
    message_buffer = message.c_str();    

    //cout << "message_buffer: " << message_buffer << endl;
    //cout << "size of message_buffer = " << message_length << endl;

    for(int i = 0; i < message_length+1; i++)
    {
        if(i == message_length)
            send_message[i+6] = '\0';
        else
            send_message[i+6] = message_buffer[i];

    }

    Result = write(tcp_SocketFileDescriptor, send_message, (message_length+6+1) );
    if(0 > Result){ 
        error("ERROR writing to socket");
    }

}



void print_instructions()
{
    cout << endl << "Found Users in Subnet. What would you like to do?" << endl;
    cout << "0 = Connect To User X" << endl;
    cout << "1 = Request User List" << endl;
    cout << "2 = Text Message to User X" << endl;
    cout << "3 = Print List of UDP Users" << endl;
    cout << "5 = Discontinue Communication with User X" << endl;
    cout << "9 = end" << endl;
}




void tcp_connect(int user_id)
{   
    cout << endl << "Trying to Connect to " << friends_list[user_id]->client_username<< "@" << friends_list[user_id]->client_hostname <<  " ..." << endl;

    tcp_SocketFileDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(0 > tcp_SocketFileDescriptor){
        error("ERROR opening socket");
    }

    //cout << "pc name = " << friends_list[0]->client_pc_name << endl;

    const char* Server_name = friends_list[user_id]->client_pc_name;


   tcp_Server = gethostbyname(Server_name);
    if(NULL == tcp_Server){
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &tcp_ServerAddress, sizeof(tcp_ServerAddress));
    tcp_ServerAddress.sin_family = AF_INET;
    bcopy((char *)tcp_Server->h_addr, (char *)&tcp_ServerAddress.sin_addr.s_addr, tcp_Server->h_length);
    tcp_ServerAddress.sin_port = htons(friends_list[user_id]->client_tcp_port);

    //Connect to server
    if(0 > connect(tcp_SocketFileDescriptor, (struct sockaddr *)&tcp_ServerAddress, sizeof(tcp_ServerAddress))){
        error("ERROR connecting");
     }
     else 
        cout <<"Connecting to Server Successful..." << endl;

    send_tcp_request();


    Result = read(tcp_SocketFileDescriptor, Buffer, BUFFER_SIZE-1);
    if(0 > Result){ 
        error("ERROR reading from socket");
    }
  
    if(Buffer[5] == 5) //to see if recieved a Accept Communcation Message
       {
         cout << "Recevied Accept Messaged." << endl;
        cout << "Successfully Connected to " << friends_list[user_id]->client_username << "@" << friends_list[user_id]->client_hostname << "(User " << user_id << ")" << endl;
        }
    else 
        cout << "Did not Recevied Accept. Maybe not Successfully connected to User " << user_id << endl;

}

void tcp_dissconnect(int user_id)
{
    tcp_dis_buffer[0] = 'P'; tcp_dis_buffer[1] = '2'; tcp_dis_buffer[2] = 'P'; tcp_dis_buffer[3] = 'I';
    tcp_dis_buffer[4] =  0; tcp_dis_buffer[5] = 10;

    cout << endl << "Sending Discontinue Communication Message" << endl;

    Result = write(tcp_SocketFileDescriptor, tcp_dis_buffer, 6);
    if(Result < 0)
        cout << "error. disconnect message did not send correctly"<< endl;
    else 
        cout << "Successfully Disconnected TCP Connection with " << friends_list[user_id]->client_username << "@" << friends_list[user_id]->client_hostname << " (User " << user_id << ")" << endl;

}


void talk()
{
    int restart_flag = 0;
    struct termios SavedTermAttributes;
    char RXChar;

    print_instructions();
    write(STDOUT_FILENO, ">", 1); 
    write(STDOUT_FILENO, " ", 1); 
    //int tcp_poll_value = 0;


    SetNonCanonicalMode(STDIN_FILENO, &SavedTermAttributes);
    
    tcp[0].fd = tcp_NewSocketFileDescriptor;
    tcp[0].events = POLLIN;

    udp[0].fd = udp_normal_SocketFileDescriptor;
    udp[0].events = POLLIN;

    listen(tcp_SocketFileDescriptor, 5);

     while(1)
     {
        udp_poll_value = poll(udp, 1, udp_timeout);

        if(udp_poll_value < 0)
                cout << "error: poll failed" << endl;
        else if(udp_poll_value == 0)
                {
                    //timeout
                }
        else if (udp_poll_value > 0)
            {
                cout << "recieve UDP packet" << endl;
                Result = recvfrom(udp_normal_SocketFileDescriptor, recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&udp_ClientAddress, &udp_ClientLength);
                    if(0 > Result)
                    error("ERROR receive from client");
                    check_udp();

            }
        



/*

        tcp_poll_value = poll(tcp, 1, tcp_timeout);

        if(tcp_poll_value < 0)
            cout << "TCP poll failed" << endl;
        else if(tcp_poll_value == 0)
            {
                cout <<"timeout" << endl;
            }
        else if(tcp_poll_value > 0)
        {
            if(tcp[0].revents & POLLIN)
               {
                    write(2, "recieved_tcp_packet", 20); 
                   // listen(tcp_SocketFileDescriptor, 5);
                    Result = read(tcp_NewSocketFileDescriptor, tcp_poll_buffer, BUFFER_SIZE-1);
                    printf("\n");
                    if(tcp_poll_buffer[0] != 10)
                     {  
                        for(int i = 0; i < 10; i++)
                            printf("Buffer[%d] = %d \n", i , tcp_poll_buffer[i]);
                    }

                    if(0 > Result)
                        error("ERROR reading from socket");
                     //check_tcp();

               } 
        }
        
*/
        if(restart_flag == 0)
        {
            write(STDOUT_FILENO, ">", 1); 
            write(STDOUT_FILENO, " ", 1); 
            restart_flag = 1;
        }



        read(STDIN_FILENO, &RXChar, 1);
        if(0x04 == RXChar)
        { // C-d
            break;
        }
        else
        {
            if(isprint(RXChar) && RXChar != 0x5B && RXChar != 0x41 && RXChar != 0x42) 
            {
                write(STDOUT_FILENO, &RXChar, 1);  
                command_string = command_string + RXChar;
            }
            if(RXChar == 0x08 || RXChar == 0x7F)//backspace
            {
                if(command_string.size()> 0)
                 {       
                    write(STDOUT_FILENO, backspace.c_str(), backspace.length());
                    command_string.erase(command_string.size() - 1);
                }
                else
                    write(STDOUT_FILENO, bell.c_str(), bell.length());
            }

            if(RXChar == 0x0A)//pressed enter
                {
                    if(command_string.compare(0, 1, "0") == 0)//want to connect to user X
                    {
                        tcp_connect(0);
                    }
                     if(command_string.compare(0, 1, "1") == 0)//want request user list
                    {
                        request_user_list();       
                    }
                    if(command_string.compare(0, 1, "2") == 0)//want to send message to user X
                    {
                        send_message();

                        cout << endl;

                       Result = read(tcp_SocketFileDescriptor, tcp_recieve_buffer, BUFFER_SIZE-1);

                       Result = read(tcp_SocketFileDescriptor, tcp_recieve_buffer, BUFFER_SIZE-1);
                         if(0 > Result)
                        error("ERROR reading from socket");

                        cout << "(" << friends_list[0]->client_username << ")" << " >> " ;

                       for(int i = 0; i < 1024; i++)
                        {   
                            char c = tcp_recieve_buffer[i+6];

                            if(c == '\0')
                                break;

                            printf("%c", tcp_recieve_buffer[i+6]);
                        }



                    } 
                    if(command_string.compare(0, 1, "3") == 0)//want to send message to user X
                    {
                        print_friends();
                        
                    }   
                     if(command_string.compare(0, 1, "5") == 0)//want to send message to user X
                    {
                        tcp_dissconnect(0);

                    }
                    if(command_string.compare(0, 1, "9") == 0)//want to send message to user X
                    {
                        send_udp_closing();
                        close(tcp_SocketFileDescriptor);
                        close(tcp_NewSocketFileDescriptor);
                        close(udp_SocketFileDescriptor);
                        cout << "Exiting" << endl;
                        exit(1);
                    }


                    restart_flag = 0;
                    cout << endl;
                    command_string.clear();
                }

            }




        }//while(1)

}//void talk()




int main(int argc, char *argv[])
{
   
    char Buffer[BUFFER_SIZE];

    
   // udp_portnumber = atoi(argv[1]);

  /*  if(argv[1] == NULL)
        udp_portnumber = 50550;
    else if((1 > udp_portnumber)||(65535 < udp_portnumber)){
        fprintf(stderr,"Port %d is an invalid port number\n", udp_portnumber);
        exit(0);
    }
    */

    udp_portnumber = 50559;
    tcp_portnumber = 50558;
    udp_portnumber_global = udp_portnumber;
    tcp_portnumber_global = tcp_portnumber;




    // Create UDP broadcast socket
    udp_SocketFileDescriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(0 > udp_SocketFileDescriptor)
        error("ERROR opening socket");

    //Creating UDP listening socket
    udp_normal_SocketFileDescriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(0 > udp_normal_SocketFileDescriptor)
        error("ERROR opening socket");
    
    
    // Set UDP socket to enable broadcast
    BroadcastEnable = 1;
    Result = setsockopt(udp_SocketFileDescriptor, SOL_SOCKET, SO_BROADCAST, &BroadcastEnable, sizeof(BroadcastEnable));
    if(0 > Result){
        close(udp_SocketFileDescriptor);
        error("ERROR setting socket option");
    }
    
    // Setup UDP ServerAddress data structure
    bzero((char *) &udp_bc_ServerAddress, sizeof(udp_bc_ServerAddress));
    udp_bc_ServerAddress.sin_family = AF_INET;
    udp_bc_ServerAddress.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    udp_bc_ServerAddress.sin_port = htons(udp_portnumber);


    bzero((char *) &udp_normal_ServerAddress, sizeof(udp_normal_ServerAddress));
    udp_normal_ServerAddress.sin_family = AF_INET;
    udp_normal_ServerAddress.sin_addr.s_addr = INADDR_ANY;
    udp_normal_ServerAddress.sin_port = htons(udp_portnumber_global);


     // Binding UDP socket to port
      if(0 > bind(udp_normal_SocketFileDescriptor, (struct sockaddr *)&udp_normal_ServerAddress, sizeof(udp_normal_ServerAddress))){ 
        error("ERROR on normal binding");
    }

    ufds[0].fd = udp_normal_SocketFileDescriptor;
    ufds[0].events = POLLIN;





    udp_ClientLength = sizeof(udp_ClientAddress);



    //Getting username and hostname
    my_username = getlogin();
    if ( gethostname(my_hostname, 1024) < 0)
        cout << "ERROR: Cannot get hostname\n";

    user_leng = my_username.length(); //username length WITOUT THE \0
    host_length = strlen(my_hostname); //hostname length WIHTOUT the \0
    



    //signal(SIGTERM, SignalHandler);
    //signal(SIGINT, SignalHandler);
    //signal(SIGUSR1, SignalHandler);


    //setting up my own TCP
    tcp_own_SocketFileDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(0 > tcp_own_SocketFileDescriptor){
        error("ERROR opening socket");
    }

    bzero((char *) &tcp_own_ServerAddress, sizeof(tcp_own_ServerAddress));
    tcp_own_ServerAddress.sin_family = AF_INET;
    tcp_own_ServerAddress.sin_addr.s_addr = INADDR_ANY;
    tcp_own_ServerAddress.sin_port = htons(tcp_portnumber_global);


     if(0 > bind(tcp_own_SocketFileDescriptor, (struct sockaddr *)&tcp_own_ServerAddress, sizeof(tcp_own_ServerAddress))){ 
        error("ERROR on binding");
    }

    /*listen(tcp_own_SocketFileDescriptor, 5);
    tcp_own_ClientLength = sizeof(tcp_own_ClientAddress);
    // Accept connection from client
    tcp_own_NewSocketFileDescriptor = accept(tcp_own_SocketFileDescriptor, (struct sockaddr *)&tcp_own_ClientAddress, &tcp_own_ClientLength);
    if(0 > tcp_own_NewSocketFileDescriptor){ 
        error("ERROR on accept");
    }
*/



    bzero(Buffer, BUFFER_SIZE);

    print_start_info();

    send_udp_discovery();   

    listen_udp_reply();

    talk();

   
    return 0;
}



void check_tcp()
{   
    if(Buffer[5] == 5)
    {
        write(2, "\nRecevied a TCP Accept Communication Message\n", 46);
    }
  

   //printf("%d %d", Buffer[4], Buffer[5]);
    //if(Buffer[5] == 5)
      //  write(2, "recieved_accept_packet\n",24);

}

void request_user_list()
{

    tcp_request_list_buffer[0] = 'P'; tcp_request_list_buffer[1] = '2'; tcp_request_list_buffer[2] = 'P'; tcp_request_list_buffer[3] = 'I';
    tcp_request_list_buffer[4] =  0; tcp_request_list_buffer[5] = 7;



    cout << endl << "Requesting User List: " << endl;

    Result = write(tcp_SocketFileDescriptor, tcp_request_list_buffer, 6);



}


void check_udp()
 {



     int index1 = 0; //to find first \0
                int index2 = 0; //to find second \0
      
                    //parsing for '/0'
                    for(int i = 0; i<1024; i++)
                    {
                        if(recv_buffer[10+i] == '\0' && index1 == 0)
                            index1 = i;
                        else if(recv_buffer[10+i] == '\0' && index1 != 0)
                        {
                            index2 = i;
                            break;
                        }

                    }//for parsing '/0'

                char temp_hostname[index1+1]; //
                char temp_username[index2-index1];

                string pc_name;

                for(int i = 0; i < index1+1; i++)
                    temp_hostname[i] = recv_buffer[10+i]; //gets hostname with \0

                for(int k = 0; k < index2-index1; k++)
                    temp_username[k] = recv_buffer[index1+k+10+1]; //gets user name with \0

                int temp_udpport = ntohs(*(uint16_t *)(recv_buffer+ 6)); //to get UDP port number to int
                int temp_tcpport = ntohs(*(uint16_t *)(recv_buffer+ 8)); // to get TCP port number to int

                 for(int i = 0; i < index1+1; i++) //to parse for pc number (Server)
                {
                    char c = temp_hostname[i];

                    if(c == '.')
                      break;
                    else
                     pc_name += c;
                }    

                const char* temp_pc_name = pc_name.c_str();

            
                if(recv_buffer[5] == 1) //Recived a Discover Message
                    {
                        cout << "Recevied Discover from " << temp_username << "@" << temp_hostname << " on UDP " << temp_udpport << ", TCP " << temp_tcpport << endl;
                        send_udp_reply(temp_pc_name);
                        client * peer = new client( temp_username, temp_hostname, temp_pc_name, temp_udpport, temp_tcpport);
                        friends_list.push_back(peer);
                        print_friends();
                        //talk();
                    }
                else if(recv_buffer[5] == 2)//Recived a Reply Message 
                    {
                        cout << "Recevied Reply from " << temp_username << "@" << temp_hostname << " on UDP " << temp_udpport << ", TCP " << temp_tcpport << endl;
                        client * peer = new client( temp_username, temp_hostname, temp_pc_name, temp_udpport, temp_tcpport);
                        friends_list.push_back(peer);
                        print_friends();
                        //talk();
                    }
                else if(recv_buffer[5] == 3)
                    {
                         cout << "Recevied Closing from " << temp_username << "@" << temp_hostname << " on UDP " << temp_udpport << ", TCP " << temp_tcpport << endl;
                         remove_from_list(temp_username, temp_hostname);
                    }


 }

 void remove_from_list(char* temp_username, char* temp_hostname)
 {
    int index;

    for(unsigned int i = 0; i < friends_list.size(); i++)
    {
        if( strcmp(friends_list[i]->client_username, temp_username) == 0 && strcmp(friends_list[i]->client_hostname, temp_hostname) == 0) 
            index = i;
    }

    cout <<"Removing " << temp_username << "@" << temp_hostname << " from friends_list" << endl;
    friends_list.erase(friends_list.begin() + index);

    print_friends();

    if(friends_list.size() == 0)
    {
        cout << "No More Discovered User, Sending UDP Broadast" << endl;

         send_udp_discovery();   

        listen_udp_reply();


    }
        
 }
