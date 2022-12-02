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
#include <stdlib.h>
#include <stdbool.h>
#include <dirent.h>
#define port 6969

#define file_folder "files"
#define MAX_FILE_PEERS 2
#define MAX_FILES_NO 10
#define MAX_CLIENTS 5

uint16_t file_struct_indx = 0;
uint16_t clients_indx = 0;

/// @brief Decode a raw message prefixated with type of message and length
/// @param raw_msg
/// @return new decoded message withouth length

struct client
{
    uint32_t client_id;
    bool isWriting; // wheter the client is conected to a file
} clients_table[MAX_CLIENTS];

/// @brief stats for every file created
struct file_stat
{

    char *file_name; // the name of the file
    struct client peers[MAX_FILE_PEERS];
    uint32_t peers_conn;
};

struct file_stat file_table[MAX_FILES_NO];

int decode_messaje(char *raw_msg)
{

    // ex: 5$texta
    char length[8];
    strncpy(length, raw_msg, strchr(raw_msg, '$') - raw_msg);
    int length_int = atoi(length);

    strcpy(raw_msg, strchr(raw_msg, '$') + 1);
    printf("%s,%d\n", raw_msg, length_int);
    return length_int;
}

// add to the file_table every file  in files folder
void add_files_from_folder()
{
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            // printf("%s\n", dir->d_name);

            if (strstr(dir->d_name, ".txt") != NULL)
            {

                // add it to the list
                struct file_stat curr_file;
                curr_file.file_name = dir->d_name;
                curr_file.peers_conn = 0;
                file_table[file_struct_indx++] = curr_file;

            }
        }
        closedir(d);
    }
}

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


        //add the files from the folder 
    chdir(file_folder);
    add_files_from_folder();
    chdir("..");

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
        // fflush(stdout);
        // printf("the client with fd %d wants to conn\n", activity);
        //  if anyone wants too connect
        if (FD_ISSET(sd, &readfds))
        {
            // prepare connect for client
            int len = sizeof(client);
            client_fd = accept(sd, (struct sockaddr *)&client, &len);
            printf(" new client's fd is %d\n", client_fd);

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

                // add curent client to table
                struct client curr_client;

                curr_client.client_id = curr_fd;
                curr_client.isWriting = false;
                clients_table[clients_indx++] = curr_client;

                fflush(stdout);
                int pipe_ends[2];

                size_t create_pipe = pipe(pipe_ends);

                pid_t pid = fork();

                if (pid == 0)
                {
                    // child
                    close(pipe_ends[0]); // close for read
                    bzero(msg, 100);
                    size_t read_len = read(curr_fd, msg, 100);
                    if (read_len < 0)
                    {
                        perror("(read) error");
                    }

                    int msg_len = decode_messaje(&msg);

                    if (msg_len == read_len) // TODO check for next packets if the message is in them !!!
                    {
                        perror("(read) messaged not read completly");
                    }

                    // handle the client's command to the server

                    compare_it(msg, "--create-file", "crf")
                    {

                        // get the file name
                        char file_name[128];
                        bzero(file_name, 128);

                        if (strstr(msg, "crf") != NULL)
                        {
                            strcat(file_name, msg + 4);
                        }

                        else
                            strcpy(file_name, msg + strlen("--create-file") + 1);

                        strcat(file_name, ".txt");

                        chdir(file_folder);

                        // printf("the dir is %s\n",getcwd(msg,100));
                        FILE *fp;
                        // open the file in append mode
                        if (access(file_name, F_OK) == 0)
                        {
                            // file already exists
                            printf("File with the name %s' already exists... \n", file_name);
                        }
                        else
                        {
                            printf("Succesfully created file: %s\n", file_name);
                        }
                        fp = fopen(file_name, "w");

                        // add file to file_stat struct

                        struct file_stat curr_stat;
                        curr_stat.file_name = file_name;
                        curr_stat.peers_conn = 0;

                        file_table[file_struct_indx++] = curr_stat;

                        fwrite("File just created \n", 1, strlen("File just created\n"), fp);
                        fclose(fp);

                        // go back to the parent dir
                        chdir("..");
                    }

                    else compare_it(msg, "-o", "open")
                    {
                        struct client curr_client;

                        // get the client which issued the command

                        for (int i = 0; i < clients_indx; i++)
                        {
                            if (clients_table[i].client_id == curr_fd)
                            {
                                clients_table[i].isWriting = true; // mark him as connected to a file
                                curr_client = clients_table[i];
                                break;
                            }
                        }

                        // client wants to open file
                        char file_name[32];
                        if (strstr(msg, "-o") != NULL)
                            strcpy(file_name, msg + 3);

                        else
                            strcpy(file_name, msg + 5);

                        strcat(file_name, ".txt");
                        printf("clien wants to open %s\n",file_name);
                        chdir(file_folder);

                        // mark the client as busy and file as opened by one

                        for (int i = 0; i < file_struct_indx; i++)
                        {

                            // search the file in the table and mark it
                            if (strstr(file_table[i].file_name, file_name) != NULL)
                            {

                                // mark in the table

                                if (file_table[i].peers_conn >= 2)
                                {
                                    perror("(open file)lobby already full ...\n");
                                }
                                else
                                {
                                    // add the user and increase the users connected to the file
                                    file_table[i].peers_conn += 1;
                                    if (file_table[i].peers_conn == 1)
                                        file_table[i].peers[1] = curr_client;

                                    else
                                        file_table[i].peers[0] = curr_client;
                                }
                            }
                        }
                        // just open the file in append mode
                        FILE *fp;
                        fp = fopen(file_name, "a");

                        // wait for user input
                    }

                    else compare_it(msg, "list-files", "ls")
                    {
                        // list all the names in the file_table
                        //printf("deteceted\n");
                        //char mess[1000]; 
                        for (int i = 0; i < file_struct_indx; i++)
                        {

                            printf("%s\n", file_table[i].file_name);
                            
                        }
                    }

                    // loop through client and see if he is connected to a file and append the text to it
                    // if curr_fd ==  curr_client from list then append to the file opened by him

                    write(pipe_ends[1], "[child-finished]", strlen("[child-finished]"));
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
                    bzero(msj, sizeof(msj));
                    read(pipe_ends[0], msj, 100);
                    if (strstr(msj, "exit") != NULL)
                    {

                        printf("The client[%d] disconnect abruptly... closing connection \n", curr_fd);
                        close(curr_fd);
                        FD_CLR(curr_fd, &all_fds);
                        // exit(1);
                        fflush(stdout);
                    }
                    else
                        printf("Client[%d]: %s\n", curr_fd, msj);
                    // close(curr_fd);
                }
            }
        }

        // handle the client command
    }
}