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
#include <time.h>
#define port 6969

#define file_folder "files"
#define MAX_FILE_PEERS 2
#define MAX_FILES_NO 10
#define MAX_CLIENTS 5

#define READ_END 0
#define WRITE_END 1

#define compare_it(STR1, STR2, STR3) if (strstr(STR1, STR2) != NULL || strstr(STR1, STR3) != NULL)

uint16_t file_struct_indx = 0;
uint16_t clients_indx = 0;

/// @brief Decode a raw message prefixated with type of message and length
/// @param raw_msg
/// @return new decoded message withouth length

struct client
{
    uint32_t client_id;
    bool isWriting; // wheter the client is conected to a file
    bool logged_in;
    char *file_name;
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
    raw_msg[strlen(raw_msg)] = NULL;
    // printf("%s,%d\n", raw_msg, length_int);
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
                // curr_file.file_name[strlen(dir->d_name)]=NULL;
                curr_file.peers_conn = 0;
                file_table[file_struct_indx++] = curr_file;
            }
        }
        closedir(d);
    }
}

void print_files()
{
    printf("files table \n");
    for (int i = 0; i < file_struct_indx; i++)
    {
        printf("file name: %s, peers_conn: %d \n", file_table[i].file_name, file_table[i].peers_conn);
    }
}
void encode_message(char *msg, char encoded[])
{

    // printf("%s\n",msg);
    char encoded_msg[256];

    char length[9];
    bzero(length, 9);

    sprintf(length, "%d", strlen(msg) - 1); // get the len of the message
    // printf("%s\n",length);
    // strcpy(encoded,length);
    strcat(encoded, length); // append it to encoded msg
    strcat(encoded, "$");    // append  $
    strcat(encoded, msg);    // append the message

    encoded_msg[strlen(encoded_msg)] = NULL;
    return;
}

struct client *get_client_by_fd(uint32_t curr_fd)
{
    // printf("client id: %d, curr_fd: %d \n",clients_table[i].client_id,curr_fd);
    for (int i = 0; i < clients_indx; i++)
    {
        if (clients_table[i].client_id == curr_fd)
        {
            return &clients_table[i];
        }
    }
    return NULL;
}

void print_clients()
{
    printf("clients table \n");
    for (int i = 0; i < clients_indx; i++)
    {
        printf("client id: %d, logged_in: %d , is_writting %d \n", clients_table[i].client_id, clients_table[i].logged_in, clients_table[i].isWriting);
    }
}

void print_client_info(struct client *client)
{

    printf("client info \n");
    printf("client id: %d, logged_in: %d , is_writting %d \n", client->client_id, client->logged_in, client->isWriting);
}

int respond_to_client(int curr_fd, char *msg)
{
    char encoded_msg[256];
    bzero(encoded_msg, 256);

    encode_message(msg, encoded_msg);

    // printf("encoded msg: %s\n",encoded_msg);
    if (write(curr_fd, encoded_msg, strlen(encoded_msg)) <= 0)
    {
        perror("write() error");
        return -1;
    }

    return 0;
}

int main()
{

    // create the socket
    struct sockaddr_in server;
    struct sockaddr_in client;
    struct timeval tv;

    char msgres[100];
    int optval = 1;
    fd_set all_fds;
    fd_set readfds;

    // add the files from the folder
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

            struct client new_client;

            // add it to th list

            new_client.client_id = client_fd;
            new_client.isWriting = false;
            new_client.logged_in = false;
            clients_table[clients_indx++] = new_client;

            printf("new client added to table \n");
            // print_clients();
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
                // extract the client from the table
                struct client *curr_client = get_client_by_fd(curr_fd);
                // print_client_info(curr_client);
                if (curr_client == NULL)
                {
                    perror("client not found");
                    continue;
                }

                fflush(stdout);
                // int pipe_ends[2];
                // size_t create_pipe = pipe(pipe_ends);

                // if (create_pipe < 0)
                // {
                //     perror("(pipe) error");
                // }

                // pid_t pid = fork();

                // if (pid == 0)
                //{
                //  child
                // close(pipe_ends[0]); // close for read
                char msg[256];

                bzero(msg, 256);

                // read in child
                size_t read_len = read(curr_fd, msg, 256);
                // print_clients();
                if (read_len < 0)
                {
                    perror("(read) error");
                }

                int msg_len = decode_messaje(&msg);

                printf("msg after decode is %s\n", msg);

                if (msg_len == read_len) // TODO check for next packets if the message is in them !!!
                {
                    perror("(read) messaged not read completly");
                }

                // handle the client's command to the server

                compare_it(msg, "login", "/l")
                {
                    // check if he is logged in

                    // print_client_info(curr_client);

                    if (curr_client->logged_in == true)
                    {
                        // write(pipe_ends[WRITE_END], "You are already logged in\n", strlen("You are already logged in\n"));
                        // respond to client

                        if (respond_to_client(curr_fd, "You are already logged in\n") < 0)
                        {
                            perror("respond to client error");
                        }

                        // exit(0);
                    }

                    else
                    {

                        // mark him as logged in
                        curr_client->logged_in = true;
                        // print_clients();

                        // repsod to client
                        if (respond_to_client(curr_fd, "You are now logged in\n") < 0)
                        {
                            perror("respond to client error");
                        }

                        // write(pipe_ends[WRITE_END], "You are now logged in\n", strlen("You are now logged in\n"));
                        // exit(0);
                    }
                }

                // he can execute commands only if he is logged in
                if (get_client_by_fd(curr_fd)->logged_in == false)
                {
                    if (respond_to_client(curr_fd, "You are not logged in\n") < 0)
                    {
                        perror("respond to client error");
                    }
                    // write(pipe_ends[WRITE_END], "You are not logged in\n", strlen("You are not logged in\n"));
                    /// exit(0);
                }

                // he is logged in so he can issue commands to the server
                else
                {

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
                        char message[50];
                        if (access(file_name, F_OK) == 0)
                        {
                            // file already exists
                            bzero(message, 50);
                            strcat(message, "File with the name ");
                            strcat(message, file_name);
                            strcat(message, " already exists ...\n");
                            printf("[DEBUG] File with the name %s  already exists... \n", file_name);
                            // write(pipe_ends[WRITE_END], message, strlen(message));
                        }
                        else
                        {
                            char message[50];
                            bzero(message, 50);
                            strcat(message, "File with the name ");
                            strcat(message, file_name);
                            strcat(message, " created succesfully ...\n");
                            // printf("[DEBUG] File with the name %s  already exists... \n", file_name);
                            // write(pipe_ends[WRITE_END], message, strlen(message));
                        }
                        fp = fopen(file_name, "w");

                        // add file to file_stat struct
                        struct file_stat curr_stat;
                        curr_stat.file_name = file_name;
                        curr_stat.peers_conn = 0;

                        file_table[file_struct_indx++] = curr_stat;
                        time_t t;
                        time(&t);

                        // for(int i = 0 ; i < file_struct_indx ; i++)
                        // {
                        //     printf("the name is %s\n",file_table[i].file_name);
                        // }

                        fwrite("###File just created at ", 1, strlen("###File just created at "), fp);
                        fwrite(ctime(&t), 1, strlen(ctime(&t)) - 1, fp);
                        fwrite(" by user ", 1, strlen(" by user "), fp);
                        char user_fd[10];
                        sprintf(user_fd, "%d", curr_fd);
                        strcat(user_fd, "###");
                        fwrite(user_fd, 1, strlen(user_fd), fp);

                        fclose(fp);

                        // go back to the parent dir
                        chdir("..");

                        if (respond_to_client(curr_fd, message) < 0)
                        {
                            perror("respond to client error");
                        }
                    }

                    else compare_it(msg, "edit", "open")
                    {

                        // get the client which issued the command
                        printf("client_count is %d\n", clients_indx);

                        // for (int i = 0; i < clients_indx; i++)
                        // {
                        //     if (clients_table[i].client_id == curr_fd)
                        //     {
                        //         clients_table[i].isWriting = true; // mark him as connected to a file
                        //         curr_client = clients_table[i];
                        //         break;
                        //     }
                        // }

                        // mark the current client as writing
                        curr_client->isWriting = true;

                        print_clients();

                        // client wants to open file
                        char file_name[32];
                        bzero(file_name, 32);

                        if (strstr(msg, "-o") != NULL)
                            strcpy(file_name, msg + 3);

                        else
                            strcpy(file_name, msg + 5);

                        curr_client->file_name = file_name;
                        strcat(file_name, ".txt");
                        printf("clien wants to open %s\n", file_name);
                        chdir(file_folder);

                        // mark the client as busy and file as opened by one
                        bool opened_ok = false;
                        for (int i = 0; i < file_struct_indx; i++)
                        {

                            // search the file in the table and mark it
                            if (strstr(file_table[i].file_name, file_name) != NULL)
                            {

                                // mark in the table
                                // TODO if the file is not present

                                if (file_table[i].peers_conn >= 2)
                                {
                                    perror("(open file)lobby already full ...\n");
                                    if (respond_to_client(curr_fd, "(open file)lobby already full ...\n") < 0)
                                    {
                                        perror("respond to client error");
                                    }
                                }
                                else
                                {
                                    // add the user and increase the users connected to the file
                                    opened_ok = true;
                                    file_table[i].peers_conn += 1;
                                    if (file_table[i].peers_conn == 1)
                                        file_table[i].peers[1] = *curr_client;

                                    else
                                        file_table[i].peers[0] = *curr_client;
                                }
                                break;
                            }
                        }

                        if (opened_ok)
                        {

                            print_files();

                            // just open the file in append mode
                            FILE *fp;
                            fp = fopen(file_name, "ra");

                            // sent the content of the file to user

                            char file_content[1024];

                            fseek(fp, 0, SEEK_END); // get the size of the file
                            long file_size = ftell(fp);
                            rewind(fp);

                            fread(file_content, file_size, 1, fp);

                            printf("[DEBUG] the content is: %s\n", file_content);

                            char message_to_client[2048];

                            strcat(message_to_client, "File ");
                            strcat(message_to_client, file_name);
                            strcat(message_to_client, " content is: \n");
                            strcat(message_to_client, file_content);
                            strcat(message_to_client, "\n");
                            strcat(message_to_client, "<everything you write will be appended to the file...>\n");
                            strcat(message_to_client, "<type 'close' to close the file>\n");

                            // printf("the messsage is %s\n", message_to_client);
                            if (respond_to_client(curr_fd, message_to_client) < 0)
                            {
                                perror("respond to client error");
                            }

                            // fwrite(file_content, 1, strlen(file_content), fp);
                            fclose(fp);
                        }
                    }

                    else compare_it(msg, "list-files", "ls")
                    {
                        // list all the names in the file_table
                        char response[256];
                        bzero(response, 256);

                        DIR *d;
                        struct dirent *dir;
                        chdir(file_folder);
                        d = opendir(".");
                        if (d)
                        {
                            while ((dir = readdir(d)) != NULL)
                            {
                                // printf("%s\n", dir->d_name);

                                if (strstr(dir->d_name, ".txt") != NULL)
                                {
                                    printf("name is %s\n", dir->d_name);
                                    strncat(response, dir->d_name, strlen(dir->d_name));
                                    strcat(response, "\n");
                                    // printf(" the respons is %s\n", response);
                                    // write(curr_fd,response,strlen(response));
                                }
                            }
                        }
                        if (respond_to_client(curr_fd, response) < 0)
                        {
                            perror("respond to client error");
                        }

                        // write(pipe_ends[1], response, strlen(response));
                    }
                    else compare_it(msg, "exit", "/exit")
                    {

                        // write(pipe_ends[WRITE_END], "exit", strlen("exit"));
                        if (respond_to_client(curr_fd, "exit issued ") < 0)
                        {
                            perror("respond to client error");
                        }

                        // close the connection
                        close(curr_fd);
                        // remove the client from the table
                        for (int i = 0; i < clients_indx; i++)
                        {
                            if (clients_table[i].client_id == curr_fd)
                            {
                                clients_table[i].client_id = -1;
                                clients_table[i].isWriting = false;
                                break;
                            }
                        }
                    }

                    // if the user is writing to a file just append to it and the dispplay it
                    else if (curr_client->isWriting)
                    {
                        printf("the user is writing to a file\n");
                        // get the name of the file he is writing to
                        char file_name[256];
                        bzero(file_name, 256);
                        strcpy(file_name, curr_client->file_name);
                        // for (int i = 0; i < file_struct_indx; i++)
                        // {
                        //     if (file_table[i].peers[0].client_id == curr_fd || file_table[i].peers[1].client_id == curr_fd)
                        //     {
                        //         strcpy(file_name, file_table[i].file_name);
                        //         break;
                        //     }
                        // }
                        printf("the file name he is editing is %s\n", file_name);

                        // append the message to the file
                        FILE *fp;
                        fp = fopen(file_name, "a");
                        fwrite(msg, 1, strlen(msg), fp);
                        fclose(fp);

                        // get the content of the newly edited file
                        char file_content[1024];
                        fp = fopen(file_name, "ra");
                        fseek(fp, 0, SEEK_END); // get the size of the file
                        long file_size = ftell(fp);
                        printf("the file size is %ld\n", file_size);
                        rewind(fp);

                        fread(file_content, file_size, 1, fp);
                        fclose(fp);
                        if(respond_to_client(curr_fd, file_content) < 0)
                        {
                            perror("respond to client error");
                        }
                    }

                    
                }

                // loop through client and see if he is connected to a file and append the text to it
                // if curr_fd ==  curr_client from list then append to the file opened by him

                fflush(stdout);
                // exit(0); // the process has finished
            }
            //}

            // else if (pid > 1)
            //{
            // parent

            // wait for child to finish
            //
            // close(pipe_ends[1]);
            // char msj[100];

            // bzero(msj, sizeof(msj));

            // read the output from child
            // size_t read_len = read(pipe_ends[0], msj, 100);
            // printf("read %d from child \n",read_len);
            // if (read_len < 0)
            // {
            //     perror("(read error) from child");
            // }

            char encoded_msg[256];
            bzero(encoded_msg, 256);
            // if (strstr(msj, "exit") != NULL)
            // {

            //     printf("The client[%d] disconnect abruptly... closing connection \n", curr_fd);
            //     close(curr_fd);
            //     FD_CLR(curr_fd, &all_fds);
            //     // exit(1);
            //     fflush(stdout);
            // }
            // else if (strlen(msj) == 0)
            // {
            //     // printf("cmd not found try help \n");
            //     encode_message("cmd not found try help \n", encoded_msg);
            //     write(curr_fd, encoded_msg, strlen(encoded_msg));
            // }
            // else
            //     // printf("Client[%d]: %s\n", curr_fd, msj);
            //     // encode the message
            //     encode_message(msj, encoded_msg);

            // printf("[DEBUG] the enc msg is %s\n",encoded_msg);
            //  send back to client
            //                    write(curr_fd, encoded_msg, strlen(encoded_msg));
            // close(curr_fd);
            //}
        }
    }

    // handle the client command
}
