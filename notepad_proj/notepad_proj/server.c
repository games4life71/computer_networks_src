#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <sys/select.h>

#define port 6969
#define file_folder "files"

#define compare_it(STR1, STR2, STR3) if (strstr(STR1, STR2) != NULL || strstr(STR1, STR3) != NULL)
int main()
{

    // create the socket
    struct sockaddr_in server;
    struct sockaddr_in client;
    struct timeval tv;
    char msg[100];
    char msgres[100];
    int optval = 1;
    fd_set all_fds;
    fd_set readfds;

    int sd; // socket descriptor

    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket() error");
        exit(-1);
    }
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bzero(&server, sizeof(server));
    bzero(&client, sizeof(client));

    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_family = AF_INET;

    if (bind(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        perror("bind() error");
    }

    if (listen(sd, 1) == -1)
    {
        perror("listen() error");
    }

    FD_ZERO(&all_fds);
    FD_SET(sd, &all_fds);
    int max_sd = sd; // maximum number of clients that can be connected
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    // iterative mode
    int client_fd;
    while (1)
    {

        // copy all the sockets to readfds

        bcopy(&all_fds, &readfds, sizeof(all_fds));
        int activity = select(max_sd + 1, &readfds, NULL, NULL, &tv);
        if ((activity < 0))
        {
            perror("select() error");
        }
        //fflush(stdout);
        //printf("the client with fd %d wants to conn\n", activity);
        // if anyone wants too connect
        if (FD_ISSET(sd, &readfds))
        {
            // prepare connect for client
            int len = sizeof(client);
            client_fd = accept(sd, (struct sockaddr *)&client, &len);
            printf(" new client's fd is %d\n",client_fd);


            if (client_fd < 0)
            {
                perror("(accept) error");
                continue;
            }

            FD_SET(client_fd, &all_fds); // add the new connected client to list

            // change the length of max sd
            if (max_sd < client_fd)
                max_sd = client_fd;
        }

        // check for any activity from other clients

        for (int curr_fd = 0; curr_fd <= max_sd; curr_fd++)
        {
            if (FD_ISSET(curr_fd, &readfds) && curr_fd != sd)
            {
                // handle the client activity
                // maybe threads ?? or fork

                // /printf("curr fd is %d\n",curr_fd);
                fflush(stdout);
                int pipe_ends[2];
                size_t create_pipe = pipe(pipe_ends);


                pid_t pid = fork();
                
                if (pid == 0)
                {
                    // child
                    close(pipe_ends[0]); // close for read 
                    bzero(msg,100);
                    if (read(curr_fd, msg, 100) < 0)
                    {
                        perror("(read) error");
                    }

                    //handle the client's command to the server 

                     compare_it(msg,"--create-file","crf")
                     {

                        //get the file name 
                        char file_name[128];
                        bzero(file_name,128);

                        if(strstr(msg,"crf")!= NULL)
                        {
                            strcat(file_name,msg+4);
                        }

                        else strcpy(file_name,msg+strlen("--create-file")+1);
                        
                        strcat(file_name,".txt");

                        printf("file name is %s\n",file_name);
                        chdir(file_folder);
                        
                        printf("the dir is %s\n",getcwd(msg,100));
                        FILE* fp;
                        //open the file in append mode 
                        fp = fopen(file_name,"w");
                        fwrite("File just created\n",1,strlen("File just created\n"),fp);
                        fclose(fp);
                     }

                    
                    write(pipe_ends[1],msg,strlen(msg));
                    fflush(stdout);
                    exit(0); // the process has finished
                }

                else if (pid > 1)
                {
                    // parent

                    // wait for child to finish
                    wait(NULL);
                    close(pipe_ends[1]);
                    char msj[100];
                    bzero(msj,sizeof(msj));
                    read(pipe_ends[0],msj,100);
                    if(strstr(msj,"exit") !=NULL)
                    {  

                        printf("The client[%d] disconnect abruptly... closing connection \n",curr_fd);
                         close(curr_fd);
                         FD_CLR(curr_fd,&all_fds);
                        //exit(1);
                        fflush(stdout);
                    }
                    else 
                    printf("Client[%d]: %s\n",curr_fd,msj);
                   //close(curr_fd);
                }
            }
        }

        // handle the client command
    }
}