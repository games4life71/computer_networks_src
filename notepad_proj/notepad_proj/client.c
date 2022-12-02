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
        
        // if (signal(SIGINT,signal_callback_handler))
        // {
        //     write(sd,"exit",strlen("exit"));
        //     printf("messahe sent");
        //     close(sd);
        //     exit(1);//interrupt
        // }  
     
       // fscanf(stdin,"%s",msg); //read a message from the user
    int read_length_stdin = read(0,msg,100);
    msg[read_length_stdin]=NULL;
    
    char sentmsg[1000]; // the message that will pe sent according to the protocol 
    bzero(sentmsg,100);

    char length[10];
    bzero(length,10);

    //printf("the len is %s\n",strlen(length));

    //the message first n bits until $ char will be used to get messaje length
    //10$ --> a message of length 10
  
    sprintf(length,"%d",read_length_stdin-1);
    strcat(sentmsg,length);
    printf("the message is %s\n",sentmsg);
    strcat(sentmsg,"$");   
    printf("the message is %s\n",sentmsg);
    strcat(sentmsg,msg);
    printf("the message is %s\n",sentmsg);

        if (write(sd, sentmsg, read_length_stdin+strlen(length)) == -1)
        {
            perror("write() error");
            exit(-1);
        }
        printf("message sent\n");
    }
    close(sd);
}