#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include<signal.h>
int port;
int global_sd;

int signal_callback_handler(int signum) {
    
   write(global_sd,"exit",strlen("exit"));
   printf("exit message sent ");
   close(global_sd);
   exit(1); // inttreupt
    
}

int decode_messaje(char *raw_msg)
{

    // ex: 5$texta
    char length[8];
    strncpy(length, raw_msg, strchr(raw_msg, '$') - raw_msg);
    int length_int = atoi(length);

    strcpy(raw_msg, strchr(raw_msg, '$') + 1);
    //printf("%s,%d\n", raw_msg, length_int);
    return length_int;
}


 void encode_message(char *msg,char encoded[])
{

//printf("%s\n",msg);
char  encoded_msg[256];


char length[9];
bzero(length,9);



 sprintf(length,"%d",strlen(msg)-1); //get the len of the message 
//printf("%s\n",length);
 //strcpy(encoded,length);
 strcat(encoded,length); //append it to encoded msg
 strcat(encoded,"$");   //append  $ 
 strcat(encoded,msg); //append the message 
return;

}

int main()
{

    int sd;                    // socket descriptor
    struct sockaddr_in server; // server address

    server.sin_addr.s_addr = inet_addr("0.0.0.0");
    server.sin_family = AF_INET;
    server.sin_port = htons(6969);

    // create the socket

    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket() error");
    }
    //set global_sd so we can kill il 

    global_sd = sd;
    // connect to server
    // bzero(msg,100);

    if (connect(sd, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        perror("connect() error");
        exit(-1);
    }

        char msg[100];
        //strcpy(msg, "cf");
    while (1)
    {
        
       signal(SIGINT,signal_callback_handler);
        
       
    int read_length_stdin = read(0,msg,256);


    if(read_length_stdin < 0 )
    {
        perror("read error");

    }
    //msg[read_length_stdin]=NULL;
    
    char sentmsg[1000]; // the message that will pe sent according to the protocol 
    bzero(sentmsg,100);

    encode_message(msg,sentmsg);
    
    char length[8];
    bzero(length,8);

   
  
    sprintf(length,"%d",read_length_stdin);
    
    
        if (write(sd, sentmsg, read_length_stdin+strlen(length)) == -1)
        {
            perror("write() error");
            exit(-1);
        }
        printf("[DEBUG] message sent\n");

        char read_srv[200];
        bzero(read_srv,200);
        size_t read_len = read(sd,read_srv,200);
        read_srv[read_len]=NULL;

        
        if( read_len== -1)
        {
            perror("read msg");

        }

        //decode the message from the server 

       

        int msg_len_sv = decode_messaje(&read_srv);

        
        //printf(" msg  after decode is %s\n",read_srv);
        //printf(" msg  len after decode is %d\n",strlen(read_srv));

        if(msg_len_sv +1 != strlen(read_srv))
        {
            perror("read not complete");
        }

        

        else 
        {
            printf("[SERVER] %s\n",read_srv);

        }

    }
    close(sd);
}