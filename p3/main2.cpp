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
#include "EncryptionLibrary.h"

using namespace std;

#define BUFFER_SIZE     1024

#ifndef htonll
uint64_t ntohll(uint64_t val){
    if(ntohl(0xAAAA5555) == 0xAAAA5555){
        return val;
    }
    return (((uint64_t)ntohl((uint32_t)(val & 0xFFFFFFFFULL)))<<32) | (ntohl((uint32_t)(val>>32)));
}

uint64_t htonll(uint64_t val){
    if(htonl(0xAAAA5555) == 0xAAAA5555){
        return val;
    }
    return (((uint64_t)htonl((uint32_t)(val & 0xFFFFFFFFULL)))<<32) | (htonl((uint32_t)(val>>32)));
}
#endif


void talk();
void check_tcp();
void request_user_list();
void check_udp();
void remove_from_list(char* temp_username, char* temp_hostname);
void read_from_tcp_bound_port();
void read_from_tcp_connection_port();
void send_my_list();
void authentication();

char udp_disc_buffer[BUFFER_SIZE]; //UDP discovery message
char udp_close_buffer[BUFFER_SIZE]; //UDP closing message 
char udp_reply_buffer[BUFFER_SIZE]; //UDP reply messagey
uint8_t udp_ecp_disc_buffer[BUFFER_SIZE];//UDP encripted discover
uint8_t tcp_encrip_request_buffer[BUFFER_SIZE];
uint8_t tcp_encrp_message[BUFFER_SIZE];

char recv_buffer[BUFFER_SIZE]; // incoming message

uint8_t trusta_recv_buffer[BUFFER_SIZE];//messages from ta

char tcp_request_buffer[BUFFER_SIZE]; //TCP establish communicate message
char tcp_data_message_buffer[BUFFER_SIZE];//send text message
char tcp_dis_buffer[BUFFER_SIZE]; //disconnect message
char tcp_request_list_buffer[BUFFER_SIZE]; //requesting the other person's list
char tcp_recieve_buffer[BUFFER_SIZE]; //whatever is recieved from tcp connection
char tcp_my_list_buffer[BUFFER_SIZE];//sending my own list out

char tcp_poll_buffer[BUFFER_SIZE];

int udp_portnumber_global;
int tcp_portnumber_global;
string my_username;
char my_hostname[1024];

const char* password_entered;
const char* global_user_and_password;

uint64_t returned_secret_global;
uint64_t returned_public_key_global;
uint64_t returned_modulus_global;
uint32_t returned_checksum_global;

uint32_t global_seq_high;
uint32_t global_seq_low;

uint64_t global_gen_mod;
uint64_t global_gen_public_key;
uint64_t global_gen_private_key;

int user_leng; //username length
int host_length; //hostname length

int nothing_left_to_read = 0;;


struct pollfd udp_ta[1];
int upd_ta_poll_value;
int upd_ta_timeout = 5000;


struct pollfd ufds[1];
int poll_value;
int timeout = 5000;

struct pollfd udp[1];
int udp_poll_value;
int udp_timeout = 1;

struct pollfd tcp[1];
int tcp_poll_value;
int tcp_timeout = 4000;

uint64_t global_32;


//for noncanmode
string backspace = "\b \b";
string bell = "\a";
string command_string;


//own TCP
int tcp_own_SocketFileDescriptor, tcp_own_NewSocketFileDescriptor;
socklen_t tcp_own_ClientLength;
struct sockaddr_in tcp_own_ServerAddress, tcp_own_ClientAddress;

char tcp_own_buffer[256];

//for UDP TA Boardcast
int udp_TA_SocketFileDescriptor;
struct sockaddr_in udp_TA_ServerAddress;

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

void send_encripted_udp_discovery()
{
     //set up P2P signature and make discovery type
    udp_ecp_disc_buffer[0] = 'P'; udp_ecp_disc_buffer[1] = '2'; udp_ecp_disc_buffer[2] = 'P'; udp_ecp_disc_buffer[3] = 'I';
    udp_ecp_disc_buffer[4] =  0;  udp_ecp_disc_buffer[5] = 16;
    
    uint64_t random_32 = GenerateRandomValue() & 0xFFFFFFFF;

    global_32 = random_32;
    
    PublicEncryptDecrypt(random_32, P2PI_TRUST_E,  P2PI_TRUST_N);

    uint64_t blah = htonll(random_32); 

    udp_ecp_disc_buffer[6] = (blah >> (8*0)) & 0xff;
    udp_ecp_disc_buffer[7] = (blah >> (8*1)) & 0xff; 
    udp_ecp_disc_buffer[8] = (blah >> (8*2)) & 0xff;
    udp_ecp_disc_buffer[9] = (blah >> (8*3)) & 0xff; 
    udp_ecp_disc_buffer[10] = (blah >> (8*4)) & 0xff; 
    udp_ecp_disc_buffer[11] = (blah >> (8*5)) & 0xff; 
    udp_ecp_disc_buffer[12] = (blah >> (8*6)) & 0xff; 
    udp_ecp_disc_buffer[13] = (blah >> (8*7)) & 0xff;


    // printf("Secret Number Sent = %d %d %d %d %d %d %d %d\n",
     //    udp_ecp_disc_buffer[6], udp_ecp_disc_buffer[7], udp_ecp_disc_buffer[8],
      //   udp_ecp_disc_buffer[9], udp_ecp_disc_buffer[10], udp_ecp_disc_buffer[11], udp_ecp_disc_buffer[12], udp_ecp_disc_buffer[13] );


    int user_leng = my_username.length(); //username length
    int host_length = strlen(my_hostname); //hostname length

    char username_buf[user_leng]; //converting my_username from string to a char[]
    strcpy(username_buf, my_username.c_str());

    //putting in username
    for(int i = 1; i < user_leng+2; i++)
    {
        if(i == host_length)
            udp_ecp_disc_buffer[13+i] = '\0';
        else
            udp_ecp_disc_buffer[13+i] = username_buf[i-1]; 
    }


    cout << "Sending Encrypted UDP Broadcast" << endl;
   int Result = sendto(udp_TA_SocketFileDescriptor,  udp_ecp_disc_buffer, (21), 0, (struct sockaddr *)&udp_TA_ServerAddress, sizeof(udp_TA_ServerAddress));
        if(0 > Result){ 
            error("ERROR sending discovery boardcast\n");
        }

/*
        Result = recvfrom(udp_normal_SocketFileDescriptor, recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&udp_ClientAddress, &udp_ClientLength);
        cout << "recieved " << endl;

        while(1)
        {
              Result = recvfrom(udp_normal_SocketFileDescriptor, recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&udp_ClientAddress, &udp_ClientLength);
                cout << "recieved " << endl;

                 if(recv_buffer[5] != 10)
                    break;
        }

        for(int i = 0; i < 23; i++)
        {
             printf("%d %02x \n",i, recv_buffer[i]); 

             if(i == 3)
                printf("Type\n");

             if(i == 5)
                printf("Secret Number\n");

            if(i == 13)
                printf("User\n");

        }
    
*/

}



void send_udp_discovery()
{   
    //set up P2P signature and make discovery type
    udp_disc_buffer[0] = 'P'; udp_disc_buffer[1] = '2'; udp_disc_buffer[2] = 'P'; udp_disc_buffer[3] = 'I';
    udp_disc_buffer[4] =  0;  udp_disc_buffer[5] = 1;
    
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


void listen_encrtyed_udp_reply()
{
    while(1)
    {

        poll_value = poll(udp_ta, 1, timeout);

        int self_discover_flag = 0;
        //int found_someone = 0;

        if(poll_value == 0)
        {   
            if(timeout == 5000)
            {   
                timeout = 10000;
                cout << "Cannot find Trust Anchor. Resending Broadcast. Timeout = 10s" << endl;
                send_encripted_udp_discovery();
            }
            else if(timeout == 10000)
            {   
                timeout = 20000;
                cout << "Cannot find Trust Anchor. Resending Broadcast. Timeout = 20s" << endl;
                send_encripted_udp_discovery();
            }
            else if(timeout == 20000)
            {
                timeout = 40000;
                cout << "Cannot find Trust Anchor. Resending Broadcast. Timeout = 40s" << endl;
                send_encripted_udp_discovery();
            }   
            else if(timeout == 40000)
            {
                timeout = 60000;
                cout << "Cannot find Trust Anchor. Resending Boardcast. Timeout = 60s" << endl;
                send_encripted_udp_discovery();
            }

        }

        if(udp_ta[0].revents & POLLIN)
        {
           // cout << "got recieved a UDP packet" << endl;
            Result = recvfrom(udp_TA_SocketFileDescriptor, trusta_recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&udp_ClientAddress, &udp_ClientLength);
            if(0 > Result)
                error("ERROR receive from client");

                if(trusta_recv_buffer[5] == 16)
                {
                    self_discover_flag = 1;
                    cout << "Recieved own UDP boardcast" << endl;
                }
                else
                {
                    cout << endl << "Recevied Reply From Trust Anchor" << endl;
                    self_discover_flag = 0;
                }


            if(self_discover_flag == 0) //if did not recieve own broadcast
            {
                //cout << "Singature: ";
                for(int i = 0; i < 4; i++)
                  //  printf("%c ",trusta_recv_buffer[i]);

               // cout << endl << "Type: ";
                for(int i = 4; i <6; i++)
                   // printf("%x ", trusta_recv_buffer[i]);

               // cout << endl << "Secret Number: ";
                    for(int i = 6; i < 14; i++)
                        //printf("%d ",trusta_recv_buffer[i]);
                        returned_secret_global = ntohll(*(uint64_t *)(trusta_recv_buffer + 6)); //to get UDP port number to int

                //cout << endl << "username: ";
                    for(int i = 14; i < 21; i++)
                        //printf("%c",trusta_recv_buffer[i]);

                //cout << endl << "Public Key(E): ";
                    for(int i = 21; i < 29; i++)
                        //printf("%x", trusta_recv_buffer[i]);
                        returned_public_key_global = ntohll(*(uint64_t *)(trusta_recv_buffer + 21));

              //  cout << endl << "Modulus(N): ";
                    for(int i = 29; i < 36; i++)
                       // printf("%x", trusta_recv_buffer[i]);
                        returned_modulus_global = ntohll(*(uint64_t *)(trusta_recv_buffer + 29));

               // cout << endl << "Check Sum: ";
                    for(int i = 36; i < 43; i++)
                        //printf("%x ", trusta_recv_buffer[i]);
                        returned_checksum_global = ntohll(*(uint64_t *)(trusta_recv_buffer + 36));
                
                authentication();
                break;
            } // if found someone and not own broadcast     
     
        }//if(ufds[0].revents & POLLIN)


    }//while(1)


} //listen for encrtyed udp reply


void authentication()
{
    PublicEncryptDecrypt(returned_secret_global, P2PI_TRUST_E,  P2PI_TRUST_N);
    
    if(global_32 == returned_secret_global)
        cout << endl << endl << "Secret Numbers Match! " << endl;
    else
        cout << "Error: Secret Numbers Do Not Match!" << endl;

    string user_colon_pass = my_username + ":" + password_entered;

    const char*str = user_colon_pass.c_str();

    global_user_and_password = str;

    uint64_t n, e, d;

    StringToPublicNED(str, n, e, d);

    global_gen_mod = n;
    global_gen_public_key = e;
    global_gen_private_key = d;

    if(n == returned_modulus_global && e == returned_public_key_global)
        cout << "Keys Match!" << endl << endl << "Password Provided has been Authenticated!" << endl << endl;
    else 
        cout << "Keys Do Not Match!" << endl << endl << "Password provided does not match authentication!" << endl << endl;

    //StringToPublicNED()

}

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
    cout << endl << "Found Users in Subnet. What would you like to do?" << endl << endl;
    cout << "0 = Connect To User X Using (Encrypted TCP)" << endl;
    cout << "1 = Text Message (Encrypted TCP0" << endl << endl;
    
    cout << "2 = Connect To User X (Normal TCP)" << endl;
    cout << "3 = Request User List (Normal TCP)" << endl;
    cout << "4 = Text Message to User X (Normal TCP)" << endl;
    cout << "5 = Request User's List (Noraml TCP)" << endl;
    cout << "6 = Discontinue Communication with User X (Normal TCP)" << endl << endl;

    cout << "7 = Read From TCP Connection Port" << endl;
    cout << "8 = Read From TCP Bound Port" << endl << endl;

    cout << "9 = Print List of UDP Users" << endl;
    cout << "10 = end" << endl;
}

void send_tcp_encript_request()
{
    cout << "Sending Establish Encrypted Communication Message..." << endl;
    tcp_encrip_request_buffer[0] = 'P'; tcp_encrip_request_buffer[1] = '2'; tcp_encrip_request_buffer[2] = 'P'; tcp_encrip_request_buffer[3] = 'I';
   tcp_encrip_request_buffer[4] =  0; tcp_encrip_request_buffer[5] = 11;

     for(int i = 0; i < user_leng+1; i++)
    {
        if(i == user_leng)
            tcp_encrip_request_buffer[6+i] = '\0';
        else
            tcp_encrip_request_buffer[6+i] = my_username[i]; 
    }


    uint64_t n2, e2, d2;

    StringToPublicNED(global_user_and_password, n2, e2, d2);

    uint64_t global_gen_public_key2 = htonll(global_gen_public_key); 
    uint64_t global_gen_mod2 = htonll(global_gen_mod); 

    //Sending Generated Key
    tcp_encrip_request_buffer[13] = (global_gen_public_key2 >> (8*0)) & 0xff;
    tcp_encrip_request_buffer[14] = (global_gen_public_key2 >> (8*1)) & 0xff;
    tcp_encrip_request_buffer[15] = (global_gen_public_key2 >> (8*2)) & 0xff;
    tcp_encrip_request_buffer[16] = (global_gen_public_key2 >> (8*3)) & 0xff;
    tcp_encrip_request_buffer[17] = (global_gen_public_key2 >> (8*4)) & 0xff;
    tcp_encrip_request_buffer[18] = (global_gen_public_key2 >> (8*5)) & 0xff;
    tcp_encrip_request_buffer[19] = (global_gen_public_key2 >> (8*6)) & 0xff;
    tcp_encrip_request_buffer[20] = (global_gen_public_key2 >> (8*7)) & 0xff;

    //Sending Modulus Key
     tcp_encrip_request_buffer[21] = (global_gen_mod2 >> (8*0)) & 0xff;
    tcp_encrip_request_buffer[22] = (global_gen_mod2 >> (8*1)) & 0xff;
    tcp_encrip_request_buffer[23] = (global_gen_mod2 >> (8*2)) & 0xff;
    tcp_encrip_request_buffer[24] = (global_gen_mod2 >> (8*3)) & 0xff;
    tcp_encrip_request_buffer[25] = (global_gen_mod2 >> (8*4)) & 0xff;
    tcp_encrip_request_buffer[26] = (global_gen_mod2 >> (8*5)) & 0xff;
    tcp_encrip_request_buffer[27] = (global_gen_mod2 >> (8*6)) & 0xff;
    tcp_encrip_request_buffer[28] = (global_gen_mod2 >> (8*7)) & 0xff;


     Result = write(tcp_SocketFileDescriptor, tcp_encrip_request_buffer, 29 );
    if(0 > Result){ 
        error("ERROR writing to socket");
    }

}



void tcp_encrp_connect(int user_id)
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

    send_tcp_encript_request();


    Result = read(tcp_SocketFileDescriptor, Buffer, BUFFER_SIZE-1);
    if(0 > Result){ 
        error("ERROR reading from socket");
    }
  
    if(Buffer[5] == 12) //to see if recieved a Accept Communcation Message
       {
         cout << "Recevied Accept Messaged." << endl;
        cout << "Successfully Encrypted Connected to " << friends_list[user_id]->client_username << "@" << friends_list[user_id]->client_hostname << "(User " << user_id << ")" << endl;
        }
    else 
        cout << "Did not Recevied Accept. Maybe not Successfully connected to User " << user_id << endl;

    global_seq_high = ntohll(*(uint64_t *)(Buffer + 6));
    global_seq_low = ntohll(*(uint64_t *)(Buffer + 14));




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



void send_enp_tcp_message()
{   

    cout << "here" << endl;
    tcp_encrp_message[0] = 'P';  tcp_encrp_message[1] = '2'; tcp_encrp_message[2] = 'P'; tcp_encrp_message[3] = 'I';
    tcp_encrp_message[4] =  0;   tcp_encrp_message[5] = 15; 

/*
    tcp_encrp_message[6] ='K';
    tcp_encrp_message[7] ='e';
    tcp_encrp_message[8] ='v';
    tcp_encrp_message[9] ='i';
    tcp_encrp_message[10] ='n';
    tcp_encrp_message[11] = '\0';

    for(int i = 0; i < 58; i++)
   {
       tcp_encrp_message[i] = i;
   }
*/

    
    uint64_t sequence_number = ((uint64_t)global_seq_high) << 32 | global_seq_low;

    uint8_t message[64];
    message[0] = 90;  message[1] = 90; message[2] = 'K'; message[3] = 'E';
    message[4] =  'V';   message[5] = 'I';
    message[6] = 'N';
   message[7] = '\0'; 

   for(int i = 0; i < 58; i++)
   {
        tcp_encrp_message[i] = i;
   }

   PrivateEncryptDecrypt(tcp_encrp_message,64,sequence_number+1);

  //  uint8_t random[56];
  //  GenerateRandomString(message, 64, sequence_number+1);
    

    memcpy(tcp_encrp_message+7, message, 64);
   // memcpy(tcp_encrp_message+14, random, 56);



    Result = write(tcp_SocketFileDescriptor, tcp_encrp_message, 64);
    if(Result < 0)
        cout << "Error Sending Message "<< endl;

    cout << "Result = " << Result << endl;

    
}

void talk()//asdf
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


    //cout <<"Listening for autoconnect.."<<endl;
    //listen for client
    //listen(tcp_own_SocketFileDescriptor, 5);
   // cout << "Done autoconnect! "<<endl;
  //  tcp_own_ClientLength = sizeof(tcp_own_ClientAddress);

    // Accept connection from client
  //  tcp_NewSocketFileDescriptor = accept(tcp_own_SocketFileDescriptor, (struct sockaddr *)&tcp_own_ClientAddress, &tcp_own_ClientLength);
    //if(0 > tcp_NewSocketFileDescriptor){ 
      //  error("ERROR on accept");
    //}

    //bzero(tcp_own_buffer, BUFFER_SIZE);
    // Read data from client
    //Result = read(tcp_NewSocketFileDescriptor, tcp_own_buffer, BUFFER_SIZE-1);
    //if(0 > Result){
      //  error("ERROR reading from socket");
    //}

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
                //cout <<"TCP OWN timeout" << endl;
            }
        else if(tcp_poll_value > 0)
        {
            if(tcp[0].revents & POLLIN)
               {
                    cout <<"polled at tcp_own_socket" << endl;

                   cout << "listeing..." << endl; 
                   listen(tcp_own_SocketFileDescriptor, 5);


                   cout << "reading..." << endl;
                    // Read data from client
                    Result = read(tcp_NewSocketFileDescriptor, tcp_own_buffer, BUFFER_SIZE-1);
                    if(0 > Result){
                        error("ERROR reading from socket");
                    }

                     printf("%d %d\n", tcp_own_buffer[0], tcp_own_buffer[1]); 
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
                    if(command_string.compare(0, 1, "0") == 0)//want to connect to user X enp
                    {
                        tcp_encrp_connect(0);
                    }
                     if(command_string.compare(0, 1, "1") == 0)//text encp message
                    {
                        cout <<"asdf" << endl;
                        send_enp_tcp_message();
                    }
                    if(command_string.compare(0, 1, "2") == 0)//connect tcp normal
                    {
                        tcp_connect(0);
                    } 

                    if(command_string.compare(0, 1, "3") == 0)//request user list
                    {
                        request_user_list();
                        
                    }   
                    if(command_string.compare(0, 1, "4") == 0)//want to send message to user X
                    {
                        send_message();

                        cout << endl;
                    }   
                     if(command_string.compare(0, 1, "5") == 0)//want to send message to user X
                    {
                        request_user_list();

                    }
                    if(command_string.compare(0, 1, "6") == 0)//want to send message to user X
                    {
                        tcp_dissconnect(0);
                    }
                     if(command_string.compare(0, 1, "8") == 0)//want to send message to user X
                    {
                        read_from_tcp_bound_port();
                    }
                    if(command_string.compare(0, 1, "7") == 0)//want to send message to user X
                    {
                        read_from_tcp_connection_port();
                    }
                    if(command_string.compare(0, 1, "10") == 0)//want to send message to user X
                    {
                        send_udp_closing();
                        close(tcp_SocketFileDescriptor);
                        close(tcp_NewSocketFileDescriptor);
                        close(udp_SocketFileDescriptor);
                        cout << "Exiting" << endl;
                        exit(1);
                    }
                    if(command_string.compare(0, 1, "9") == 0)//want to send message to user X
                    {
                        print_friends();
                    }

                    restart_flag = 0;
                    cout << endl;
                    command_string.clear();
                }

            }




        }//while(1)

}//void talk()


void read_from_tcp_connection_port()
{
   
   if(nothing_left_to_read == 0)
   {
        Result = read(tcp_SocketFileDescriptor, tcp_recieve_buffer, BUFFER_SIZE-1);
            if(0 > Result)
                error("ERROR reading from socket");
        
        check_tcp();

    }
    else
        cout << "There are no incoming messages." << endl; 
}


void read_from_tcp_bound_port()
{

     Result = read(tcp_NewSocketFileDescriptor, tcp_poll_buffer, BUFFER_SIZE-1);

     cout << endl;
     for(int i = 0; i < 8; i++)
        printf("%d ",tcp_poll_buffer[i]);
     cout << endl;

}


int main(int argc, char *argv[])
{
   
    char Buffer[BUFFER_SIZE];

    udp_portnumber = 50551;
    tcp_portnumber = 50558;
    udp_portnumber_global = udp_portnumber;
    tcp_portnumber_global = tcp_portnumber;

    //create UDP socket to Boarcast to Trust Anchor
    udp_TA_SocketFileDescriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(0 > udp_TA_SocketFileDescriptor){
        error("ERROR opening socket");
    }

     // Set UDP TA socket to enable broadcast
    BroadcastEnable = 1;
    Result = setsockopt(udp_TA_SocketFileDescriptor, SOL_SOCKET, SO_BROADCAST, &BroadcastEnable, sizeof(BroadcastEnable));
    if(0 > Result){
        close(udp_TA_SocketFileDescriptor);
        error("ERROR setting socket option");
    }

    // Setup ServerAddress FOR UDP TA data structure
    bzero((char *) &udp_TA_ServerAddress, sizeof(udp_TA_ServerAddress));
    udp_TA_ServerAddress.sin_family = AF_INET;
    udp_TA_ServerAddress.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    udp_TA_ServerAddress.sin_port = htons(50552);



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
    udp_bc_ServerAddress.sin_port = htons(udp_portnumber_global);


    bzero((char *) &udp_normal_ServerAddress, sizeof(udp_normal_ServerAddress));
    udp_normal_ServerAddress.sin_family = AF_INET;
    udp_normal_ServerAddress.sin_addr.s_addr = INADDR_ANY;
    udp_normal_ServerAddress.sin_port = htons(udp_portnumber_global);


    //Binding UDP socket to port
      if(0 > bind(udp_normal_SocketFileDescriptor, (struct sockaddr *)&udp_normal_ServerAddress, sizeof(udp_normal_ServerAddress))){ 
        error("ERROR on normal binding");
    }

    ufds[0].fd = udp_normal_SocketFileDescriptor;
    ufds[0].events = POLLIN;

    udp_ta[0].fd = udp_TA_SocketFileDescriptor;
    udp_ta[0].events = POLLIN;





    udp_ClientLength = sizeof(udp_ClientAddress);



    //Getting username and hostname
    my_username = getlogin();
    if ( gethostname(my_hostname, 1024) < 0)
        cout << "ERROR: Cannot get hostname\n";

    user_leng = my_username.length(); //username length WITOUT THE \0
    host_length = strlen(my_hostname); //hostname length WIHTOUT the \0
    

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



    bzero(Buffer, BUFFER_SIZE);

    string password;
    cout << "Please Enter Password For " << my_username << "> ";

    cin >> password;

    password_entered = password.c_str();


    print_start_info();

    send_encripted_udp_discovery();
  
    listen_encrtyed_udp_reply();

    send_udp_discovery();  

    listen_udp_reply();

    talk();

   
    return 0;
}



void check_tcp()
{   

    char parse_buffer[100];

    cout << endl;
    cout << "Recevied: ";
    cout << endl << "Parsed: ";
    for(int i = 0; i < 100; i++)
    {   
            

        if(i >= 5 && tcp_recieve_buffer[i] == '\0')
            break;

        parse_buffer[i] = tcp_recieve_buffer[i];
        printf("%d ",parse_buffer[i]);      
    }

    cout << endl << "Full: ";    

    for (int i = 0; i < 50; ++i)
    {
        printf("%d ",tcp_recieve_buffer[i]);
    }

      cout << endl;

    if(tcp_recieve_buffer[5] == 5)//recived a Accept Comm message
    {
        write(2, "\nRecevied a TCP Accept Communication Message\n", 46);
    }


    if(tcp_recieve_buffer[5] == 9)//received a message
    {

        cout << "(" << friends_list[0]->client_username << ")" << " >> " ;

        for(int i = 0; i < 1024; i++)
        {   
            char c = tcp_recieve_buffer[i+6];

            if(c == '\0')
                break;

            printf("%c", tcp_recieve_buffer[i+6]);
        }

    }   

    if(tcp_recieve_buffer[5]==7) //Requesting My List
        send_my_list();





}


void send_my_list()
{
    tcp_my_list_buffer[0] = 'P'; tcp_my_list_buffer[1] = '2'; tcp_my_list_buffer[2] = 'P'; tcp_my_list_buffer[3] = 'I';
    tcp_my_list_buffer[4] =  0; tcp_my_list_buffer[5] = 8;

    cout << endl << "Sending UDP Connections List...";

    tcp_my_list_buffer[6] = 0;
    tcp_my_list_buffer[7] = 0;
    tcp_my_list_buffer[8] = 0;
    tcp_my_list_buffer[9] = 1;

    tcp_my_list_buffer[10] = 0;
    tcp_my_list_buffer[11] = 0;
    tcp_my_list_buffer[12] = 0;
    tcp_my_list_buffer[13] = 0;    

    //set UDP port
    tcp_my_list_buffer[14] = htons(friends_list[0]->client_udp_port) & 0xFF; 
    tcp_my_list_buffer[15] = htons(friends_list[0]->client_udp_port) >> 8; 


    string temp_user(friends_list[0]->client_username);
    string temp_host(friends_list[0]->client_hostname);

    int user_leng = temp_user.length(); //username length
    int host_length = temp_host.length(); //hostname length

    //putting in hostname
    for(int i = 0; i < host_length+1; i++)
    {
        if(i == host_length)
            tcp_my_list_buffer[16+i] = '\0';
        else
            tcp_my_list_buffer[16+i] = friends_list[0]->client_hostname[i]; 

    }


    //set TCP port
    tcp_my_list_buffer[16+host_length+1] = htons(friends_list[0]->client_tcp_port) & 0xFF; 
    tcp_my_list_buffer[16+host_length+2] = htons(friends_list[0]->client_tcp_port) >> 8; 


    //putting in username
     for(int i = 0; i < user_leng+1; i++)
    {   
        if(i == user_leng)
            tcp_my_list_buffer[16+i+host_length + 4] = '\0';
        else
            tcp_my_list_buffer[16+i+host_length + 3] = friends_list[0]->client_username[i];
    }

    Result = write(tcp_SocketFileDescriptor, tcp_my_list_buffer, 16+host_length+user_leng+4);
    if(Result < 0)
        cout << "Error Sending My List" << endl;
    else
        cout << "Sent List" << endl;


}

void request_user_list()
{

    tcp_request_list_buffer[0] = 'P'; tcp_request_list_buffer[1] = '2'; tcp_request_list_buffer[2] = 'P'; tcp_request_list_buffer[3] = 'I';
    tcp_request_list_buffer[4] =  0; tcp_request_list_buffer[5] = 7;



    cout << endl << "Requesting User List... " << endl;

    Result = write(tcp_SocketFileDescriptor, tcp_request_list_buffer, 6);
    if(Result < 0)
        cout << "error request list" << endl;


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
