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
#define log_folder "logs"
#define MAX_FILE_PEERS 2
#define MAX_FILES_NO 50
#define MAX_CLIENTS 5

#define READ_END 0
#define WRITE_END 1

#define SMALL_SIZE 256
#define MEDIUM_SIZE 1024
#define BIG_SIZE 2048

// #define compare_it(STR1, STR2, STR3) if (strstr(STR1, STR2) != NULL || strstr(STR1, STR3) != NULL)
int compare_it_funct(char *msg, char *command1, char *command2)
{
    char *token = strtok(msg, " "); // loginaaaa

    if (strcmp(token, command1) == 0 || strcmp(token, command2) == 0)
    {
        return 1;
    }
    return 0;
}

#define compare_it(STR1, STR2, STR3) if (compare_it_funct(STR1, STR2, STR3) == 1)

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
    char file_name[128]; // the name of the file
    struct client peers[MAX_FILE_PEERS];
    uint32_t peers_conn;
    uint32_t pointer_pos;
    long long file_size;
};

struct file_stat file_table[MAX_FILES_NO];

int decode_messaje(char *raw_msg, char *msg)
{

    // ex: 4$exit
    char length[8];
    strncpy(length, raw_msg, strchr(raw_msg, '$') - raw_msg);
    //("%s\n", length);

    int length_int = atoi(length);
    if (length_int == 0)
    {

        strcpy(msg, "newline");
        return 0;
    }
    char *p = strchr(raw_msg, '$') + 1;
    // printf("%s\n", p);
    //  bzero(raw_msg,strlen(raw_msg));
    strcpy(msg, p);
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
                strcpy(curr_file.file_name, dir->d_name);
                // curr_file.file_name[strlen(dir->d_name)]=NULL;
                curr_file.peers_conn = 0;
                FILE *fp = fopen(dir->d_name, "r");
                fseek(fp, 0, SEEK_END);
                curr_file.pointer_pos = ftell(fp);
                curr_file.file_size = ftell(fp);
                fclose(fp);
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
        printf("file name: %s, peers_conn: %d  curson_pos : %d\n", file_table[i].file_name, file_table[i].peers_conn, file_table[i].pointer_pos);
    }
}

void add_files_entry(struct file_stat *entry)
{

    file_table[file_struct_indx++] = *entry;
}

void encode_message(char *msg, char encoded[])
{

    // printf("%s\n",msg);
    char encoded_msg[256];

    char length[9];
    bzero(length, 9);

    sprintf(length, "%d", strlen(msg)); // get the len of the message
    // printf("%s\n",length);
    // strcpy(encoded,length);
    strcat(encoded, length); // append it to encoded msg
    strcat(encoded, "$");    // append  $
    strcat(encoded, msg);    // append the message

    encoded_msg[strlen(encoded_msg)] = NULL;
    // printf("the encoded message is: %s\n", encoded);
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
        printf("client id: %d, logged_in: %d , is_writting %d  \n", clients_table[i].client_id, clients_table[i].logged_in, clients_table[i].isWriting);
    }
}

void print_client_info(struct client *client)
{

    printf("client info \n");
    printf("client id: %d, logged_in: %d , is_writting %d \n", client->client_id, client->logged_in, client->isWriting);
}

int respond_to_client(int curr_fd, char *msg)
{
    char encoded_msg[BIG_SIZE];
    bzero(encoded_msg, BIG_SIZE);

    encode_message(msg, encoded_msg);
    // printf("encoded msg is : %s\n", encoded_msg);

    // printf("encoded msg: %s\n",encoded_msg);
    if (write(curr_fd, encoded_msg, strlen(encoded_msg)) <= 0)
    {
        perror("write() error");
        return -1;
    }
    // printf("The message is sent to the client %s\n ", msg);
    return 0;
}

struct file_stat *get_file_by_name(char *file_name)
{
    for (int i = 0; i < file_struct_indx; i++)
    {
        if (strcmp(file_table[i].file_name, file_name) == 0)
        {
            return &file_table[i];
        }
    }
    return NULL;
}

void log_event(char *event, char *log_file)
{
    // chdir(log_folder);
    FILE *fp = fopen(log_file, "a");
    fwrite(event, strlen(event), 1, fp);
    fclose(fp);
    // printf("the curent folder is: %s \n", getcwd(NULL, 0));
    //  chdir("..");
}
char log_file_global[100];

void signal_callback_handler(int signum)
{

    char event[100];
    bzero(event, 100);
    sprintf(event, "server is shutting down\n");
    log_event(event, log_file_global);

    exit(1);
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
    // printf("files added from folder \n");
    // print_files();
    chdir("..");

    int sd; // socket descriptor

    // create the socket
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("socket() error");
        exit(-1);
    }

    // set the socket options
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bzero(&server, sizeof(server));
    bzero(&client, sizeof(client));

    // configure the server
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY); // use any adress 0.0.0.0
    server.sin_family = AF_INET;                // intra net protocol

    // bind the socket to the server
    if (bind(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
    {
        perror("bind() error");
    }

    // listen to the socket
    if (listen(sd, 1) == -1)
    {
        perror("listen() error");
    }

    // initialize the file descriptor set
    FD_ZERO(&all_fds);
    FD_SET(sd, &all_fds);
    int max_sd = sd; // maximum number of clients that can be connected
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    int client_fd;

    // create the files folder
    int res = mkdir(file_folder, 0777);

    // create the folders for the files and the logs
    if (res == -1 && strstr(strerror(errno), "File exists") != NULL)
    {
        printf("[DEBUG] the folder %s already exists\n", file_folder);
    }

    res = mkdir(log_folder, 0777);
    if (res == -1 && strstr(strerror(errno), "File exists") != NULL)
    {
        printf("[DEBUG] the folder %s already exists\n", log_folder);
    }

    // create a new log file for this session
    char log_file_name[100];
    bzero(log_file_name, 100);
    // get the date
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    sprintf(log_file_name, "%d-%d-%d_%d:%d:%d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    strcat(log_file_name, ".txt");
    // printf("log file name is %s\n", log_file_name);

    // create the log_file
    chdir(log_folder);
    FILE *fp;
    fp = fopen(log_file_name, "w");
    fwrite("server succesfully created\n", 1, strlen("server succesfully created\n"), fp);
    fclose(fp);
    // copy the path into log_file_name
    // get the dir path
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    strcat(cwd, "/");
    strcat(cwd, log_file_name);
    strcpy(log_file_name, cwd);
    strcpy(log_file_global, log_file_name);
    // printf("log file name is %s\n", log_file_name);

    chdir("..");

    while (1)
    {

        // copy all the sockets to readfds

        bcopy(&all_fds, &readfds, sizeof(all_fds));
        // select the active fds
        int activity = select(max_sd + 1, &readfds, NULL, NULL, &tv);

        if ((activity < 0))
        {

            printf("Waiting for clients to connect...\n");
        }

        // fflush(stdout);
        // printf("the client with fd %d wants to conn\n", activity);

        //  if anyone wants too connect
        if (FD_ISSET(sd, &readfds))
        {
            // prepare connect for client
            int len = sizeof(client);
            client_fd = accept(sd, (struct sockaddr *)&client, &len);
            // printf(" new client's fd is %d\n", client_fd);

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

            // if(respond_to_client(client_fd,"Welcome to the server")<0)
            //     perror("error sending welcome message");

            printf("[DEBUG] new client added to table \n");

            char event[100];
            bzero(event, 100);
            sprintf(event, "new client connected with fd %d\n", client_fd);
            log_event(event, log_file_name);

            print_clients();
            // change the length of max sd
            if (max_sd < client_fd)
                max_sd = client_fd;
        }

        // check for any activity from other clients
        for (int curr_fd = 0; curr_fd <= max_sd; curr_fd++)
        {

            signal(SIGINT, signal_callback_handler);

            if (FD_ISSET(curr_fd, &readfds) && curr_fd != sd)
            {
                // handle the client activity
                // maybe threads ?? or fork

                // extract the client from the table
                struct client *curr_client = get_client_by_fd(curr_fd);

                // print_client_info(curr_client);
                if (curr_client == NULL)
                {
                    // perror("client not found");
                    continue;
                }

                fflush(stdout);

                char msg[BIG_SIZE];
                char msg_cpy[BIG_SIZE];
                char raw_msg[BIG_SIZE];
                bzero(raw_msg, BIG_SIZE);
                bzero(msg_cpy, BIG_SIZE);
                bzero(msg, BIG_SIZE);

                size_t read_len = read(curr_fd, raw_msg, BIG_SIZE);
                printf("read len is %d and len of msg is %d and the raw msg is %s \n", read_len, strlen(raw_msg), raw_msg);

                // print_clients();

                if (read_len < 0)
                {
                    perror("(read) error");
                }
                int msg_len;
                if (strlen(raw_msg) != 0)
                {
                    msg_len = decode_messaje(raw_msg, msg); // decode the message and return the length of the decoded message
                }
                else
                {
                    msg_len = 0;
                    strcpy(msg, raw_msg);
                }
                strcpy(msg_cpy, msg); // make a copy of the decoded message to use it later

                // printf("read len is %d and len of msg is %d\n", read_len, strlen(msg));

                msg[strcspn(msg, "\n")] = NULL; // eliminate the new line character

                printf("msg after decode is %s with length %d\n", msg, strlen(msg));

                if (msg_len == read_len) // TODO check for next packets if the message is in them !!!
                {
                    perror("(read) messaged not read completly");
                }

                // handle the client's command to the server
                // printf("message is %s\n", msg);

                if (strlen(msg) == 0 && curr_client->isWriting == true)
                {
                    printf("[DEBUG] the message is empty\n");
                    strcat(msg, "\n");
                }

                compare_it(msg, "exit", "/exit")
                {
                    printf("[DEBUG] client wants to exit\n");

                    // struct file_stat *curr_file;
                    if (curr_client->isWriting)
                    {
                        // get_client_by_fd(curr_fd)->isWriting = false;
                        //  get the file name he is editing
                        char file_name[SMALL_SIZE];

                        bzero(file_name, SMALL_SIZE);

                        strcpy(file_name, get_client_by_fd(curr_fd)->file_name);

                        printf("[DEBUG] the file name is %s\n", file_name);
                        struct file_stat *curr_file = get_file_by_name(file_name);

                        // print_client_info(get_client_by_fd(curr_fd));
                        curr_file->peers_conn--;
                        print_files();

                        // struct client_stat* curr_client = &curr_file->peers[0];
                        if (curr_file->peers[0].client_id == curr_fd)
                        {
                            curr_file->peers[0].client_id = -1;
                        }
                        else
                        {
                            curr_file->peers[1].client_id = -1;
                        }
                        print_files();
                    }
                    // curr_file->peers_conn--;
                    // remove the client from the file

                    struct client *curr_client = get_client_by_fd(curr_fd);
                    curr_client->isWriting = false;
                    curr_client->logged_in = false;
                    curr_client->client_id = -1;

                    char event[100];
                    bzero(event, 100);
                    sprintf(event, "client with fd %d disconnected\n", curr_fd);
                    log_event(event, log_file_name);

                    // fclose(curr_fd);
                    continue;
                }
                compare_it(msg, "login", "/l")
                {
                    // check if he is logged in

                    // print_client_info(curr_client);
                    if (curr_client->isWriting == true)
                    {
                        if (respond_to_client(curr_fd, "You are writing to a file.. can't execute command unless '!close'\n") < 0)
                        {
                            perror("respond to client error");
                        }
                        continue;
                    }

                    if (curr_client->logged_in == true)
                    {
                        // respond to client

                        if (respond_to_client(curr_fd, "You are already logged in ! \n") < 0)
                        {
                            perror("respond to client error");
                        }
                    }

                    else
                    {

                        // mark him as logged in
                        curr_client->logged_in = true;
                        // print_clients();

                        // repsod to client
                        printf("marked as logged in\n");
                        char event[100];
                        bzero(event, 100);
                        sprintf(event, "client with fd %d logged in\n", curr_fd);
                        log_event(event, log_file_name);

                        if (respond_to_client(curr_fd, "You are now logged in\n") < 0)
                        {
                            perror("respond to client error");
                        }

                        // write(pipe_ends[WRITE_END], "You are now logged in\n", strlen("You are now logged in\n"));
                        // exit(0);
                    }

                    continue;
                }

                else compare_it(msg, "help", "/h")
                {
                    printf("client wants help\n");
                    char response[1024];
                    bzero(response, 1024);
                    strcat(response, "Commands:\n");
                    strcat(response, "\n");
                    strcat(response, "create file <file_name> / crf <file_name>  - create a file\n");
                    strcat(response, "peek <file_name> - peek at a file without opening it \n");
                    strcat(response, "open <file_name> - open a file\n");
                    strcat(response, "list-files/ls  - list all the files in the server\n");
                    strcat(response, "!close - close the file you opened\n");
                    strcat(response, "exit - exit the server\n");
                    strcat(response, "login - login to the server\n");
                    strcat(response, "help - show this message\n");
                    strcat(response, "whoami - show your id \n");
                    strcat(response, "file-info <file_name> - get info about a file\n");
                    strcat(response, "seekl <value>  -seek left info a file \n");
                    strcat(response, "seekr <value>  -seek right info a file \n");
                    strcat(response, "delete <file_name> - delete a file\n");
                    strcat(response, "get-pos - get the current position in the file\n");
                    strcat(response, "backspace <value> - delete <value> characters from the current position\n");
                    if (respond_to_client(curr_fd, response) < 0)
                    {
                        perror("respond to client error");
                    }
                    continue;
                }

                // print_clients();
                // he can execute commands only if he is logged in
                // printf("the message is %s\n", msg);

                if (get_client_by_fd(curr_fd)->logged_in == false)
                {
                    // printf("got here\n");
                    if (respond_to_client(curr_fd, "You are not logged in... login with 'login' or see 'help' section \n") < 0)
                    {
                        perror("respond to client error");
                    }
                    // write(pipe_ends[WRITE_END], "You are not logged in\n", strlen("You are not logged in\n"));
                    /// exit(0);
                }

                // else if(1){printf("alalaalalla");}

                // he is logged in so he can issue commands to the server
                else
                {
                    // printf("got here in else inside \n");

                    compare_it(msg, "create-file", "crf")
                    {

                        if (curr_client->isWriting == true)
                        {
                            if (respond_to_client(curr_fd, "You are writing to a file.. can't execute command unless '!close'\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

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

                        // printf("file name is %s\n",file_name);
                        FILE *fp;
                        // message to be sent to the client
                        char message[SMALL_SIZE];
                        bzero(message, SMALL_SIZE);

                        if (access(file_name, F_OK) == 0)
                        {
                            // file already exists
                            bzero(message, SMALL_SIZE);
                            strcat(message, "File with the name ");
                            strcat(message, file_name);
                            strcat(message, " already exists ...\n");
                            printf("[DEBUG] File with the name %s  already exists... \n", file_name);
                            // write(pipe_ends[WRITE_END], message, strlen(message));
                            if (respond_to_client(curr_fd, message) < 0)
                            {
                                perror("respond to client error");
                            }
                        }
                        else
                        { // file does not exist
                            fp = fopen(file_name, "w");

                            // add file to file_stat struct

                            // print_files();
                            char message[50];
                            bzero(message, 50);
                            strcat(message, "File with the name ");
                            strcat(message, file_name);
                            strcat(message, " created succesfully ...\n");

                            if (respond_to_client(curr_fd, message) < 0)
                            {
                                perror("respond to client error");
                            }

                            char event[100];
                            bzero(event, 100);
                            sprintf(event, "client with fd %d created file %s\n", curr_fd, file_name);
                            log_event(event, log_file_name);

                            // printf("[DEBUG] File with the name %s  already exists... \n", file_name);
                            // write(pipe_ends[WRITE_END], message, strlen(message));
                            time_t t;
                            time(&t);

                            fwrite("###File just created at ", 1, strlen("###File just created at "), fp);
                            fwrite(ctime(&t), 1, strlen(ctime(&t)) - 1, fp);
                            fwrite(" by user ", 1, strlen(" by user "), fp);
                            char user_fd[10];
                            sprintf(user_fd, "%d", curr_fd);
                            strcat(user_fd, "###");
                            fwrite(user_fd, 1, strlen(user_fd), fp);
                            // get the position of the cursor

                            size_t pos = ftell(fp);
                            printf("the position is %d\n", pos);

                            struct file_stat curr_stat;
                            strcpy(curr_stat.file_name, file_name);
                            // curr_stat.file_name = file_name;
                            curr_stat.peers_conn = 0;
                            curr_stat.pointer_pos = pos; // start from the beginning

                            add_files_entry(&curr_stat);

                            fclose(fp);

                            // go back to the parent dir
                            chdir("..");

                            print_files();
                        }

                        // printf("[DEBUG] the message is %s\n", message);
                        //  if (respond_to_client(curr_fd, message) < 0)
                        //  {
                        //      perror("respond to client error");
                        //  }
                    }

                    else compare_it(msg, "delete", "/del")
                    {

                        if (curr_client->isWriting == true)
                        {
                            if (respond_to_client(curr_fd, "You are writing to a file.. can't execute command unless '!close'\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        // delete the file specified
                        char file_name[SMALL_SIZE];
                        // disconnect all the users from the file
                        // char file_name[SMALL_SIZE];
                        bzero(file_name, SMALL_SIZE);
                        strcat(file_name, msg + 7);
                        strcat(file_name, ".txt");
                        printf("[DEBUG] file name is %s\n", file_name);
                        struct file_stat *curr_file = get_file_by_name(file_name);
                        // printf(" the file name is %s from pointer ",curr_file->file_name);
                        //  print_clients();

                        // for all clients
                        bool found = false;
                        for (int i = 0; i < clients_indx; i++)
                        {
                            struct client *curr_client = &clients_table[i];
                            print_client_info(curr_client);
                            // if the client is connected to the file

                            if (curr_client->isWriting == true)
                            {
                                if (strcmp(curr_client->file_name, file_name) == 0)
                                {

                                    // cant remove it because someones is connected to it
                                    char message[SMALL_SIZE];
                                    bzero(message, SMALL_SIZE);
                                    strcat(message, "File with the name ");
                                    strcat(message, file_name);
                                    strcat(message, " is being edited by another user, please try again later ...\n");
                                    printf("[DEBUG] File with the name %s  is being edited by another user, please try again later... \n", file_name);

                                    if (respond_to_client(curr_fd, message) < 0)
                                    {
                                        perror("respond to client error");
                                    }
                                    found = true;
                                    break;
                                }
                            }
                        }

                        if (found == true)
                        {
                            continue;
                        }

                        chdir(file_folder);
                        printf("the current directory is %s\n", getcwd(NULL, 0));
                        // delete the file specified
                        if (remove(file_name) == 0)
                        {

                            // remove from the table
                            //  struct file_stat *curr_file = get_file_by_name(file_name);
                            //  curr_file->file_name[0] = '\0';
                            //  curr_file->peers_conn = 0;
                            //  curr_file->pointer_pos = 0;

                            for (int i = 0; i < file_struct_indx; i++)
                            {
                                if (strcmp(file_table[i].file_name, file_name) == 0)
                                {
                                    file_table[i].file_name[0] = '\0';
                                    file_table[i].peers_conn = 0;
                                    file_table[i].pointer_pos = 0;
                                    // printf("the file name is %s\n", file_table[i].file_name);
                                }
                            }
                            printf("File %s deleted successfully\n", file_name);
                            char message[SMALL_SIZE];
                            bzero(message, SMALL_SIZE);
                            strcat(message, "File ");
                            strcat(message, file_name);
                            strcat(message, " deleted successfully...\n");
                            if (respond_to_client(curr_fd, message) < 0)
                            {
                                perror("respond to client error");
                            }
                            char event[100];
                            bzero(event, 100);
                            sprintf(event, "client with fd %d deleted file %s\n", curr_fd, file_name);
                            log_event(event, log_file_name);
                            // go back to the parent dir
                        }
                        else
                        {
                            printf("Unable to delete the file...\n");
                            char message[SMALL_SIZE];
                            bzero(message, SMALL_SIZE);
                            strcat(message, "Unable to delete the file\n");
                            if (respond_to_client(curr_fd, message) < 0)
                            {
                                perror("respond to client error");
                            }
                        }
                        chdir("..");
                    }

                    else compare_it(msg, "peek", "/pk")
                    {
                        // check if the client has opened a file
                        if (curr_client->isWriting == true)
                        {
                            if (respond_to_client(curr_fd, "You are writing to a file.. can't execute command unless '!close'\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }
                        // open the file and peek it
                        char file_name[128];
                        bzero(file_name, 128);

                        // get the file name
                        if (strstr(msg, "/pk") != NULL)
                        {
                            strcat(file_name, msg + 3);
                        }

                        else
                            strcpy(file_name, msg + strlen("peek") + 1);

                        strcat(file_name, ".txt");

                        printf("[DEBUG] the file name is %s and the len is %d\n", file_name, strlen(file_name));

                        FILE *fp;
                        chdir(file_folder);
                        // check if the file exists
                        if (access(file_name, F_OK) == -1)
                        {
                            printf("File %s does not exist\n", file_name);
                            char message[SMALL_SIZE];
                            bzero(message, SMALL_SIZE);
                            strcat(message, "File ");
                            strcat(message, file_name);
                            strcat(message, " does not exist...\n");
                            if (respond_to_client(curr_fd, message) < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        fp = fopen(file_name, "r");
                        if (fp < 0)
                        {
                            perror("file open error");
                        }
                        char file_content[BIG_SIZE];
                        bzero(file_content, BIG_SIZE);

                        fseek(fp, 0, SEEK_END); // get the size of the file
                        long file_size = ftell(fp);
                        rewind(fp);

                        fread(file_content, file_size, 1, fp);
                        fclose(fp);

                        printf("[DEBUG] the content is: \n %s\n", file_content);

                        char message_to_client[BIG_SIZE];
                        bzero(message_to_client, BIG_SIZE);
                        // fclose(fp);

                        strcat(message_to_client, "File ");
                        strcat(message_to_client, file_name);
                        strcat(message_to_client, " content is: ");
                        strcat(message_to_client, file_content);
                        strcat(message_to_client, "\n");

                        // printf("the messsage is %s\n", message_to_client);
                        if (respond_to_client(curr_fd, message_to_client) < 0)
                        {
                            perror("respond to client error");
                        }

                        // fwrite(file_content, 1, strlen(file_content), fp);
                    }

                    else compare_it(msg, "get-pos", "/get-pos")
                    {
                        if (curr_client->isWriting == false)
                        {
                            if (respond_to_client(curr_fd, "You are not writing to a file.. can't execute command unless you open one ! \n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        // get the file name
                        char file_name[128];
                        bzero(file_name, 128);

                        struct file_stat *curr_file = get_file_by_name(curr_client->file_name);

                        // printf("the current pos in file  is %d\n" ,curr_file.pointer_pos );
                        char message_to_client[BIG_SIZE];
                        bzero(message_to_client, BIG_SIZE);
                        // fclose(fp);

                        strcat(message_to_client, "File ");
                        strcat(message_to_client, curr_client->file_name);
                        strcat(message_to_client, " current position is: ");
                        char pos[10];
                        sprintf(pos, "%d", curr_file->pointer_pos);
                        strcat(message_to_client, pos);
                        strcat(message_to_client, "\n");

                        // printf("the messsage is %s\n", message_to_client);
                        if (respond_to_client(curr_fd, message_to_client) < 0)
                        {
                            perror("respond to client error");
                        }
                    }

                    else compare_it(msg, "whoami", "who")
                    {

                        if (curr_client->isWriting == true)
                        {
                            if (respond_to_client(curr_fd, "You are writing to a file.. can't execute command unless '!close'\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        char message[50];
                        bzero(message, 50);
                        strcat(message, "You are user ");
                        char user_fd[10];
                        sprintf(user_fd, "%d", curr_fd);
                        strcat(message, user_fd);
                        strcat(message, "\n");
                        if (respond_to_client(curr_fd, message) < 0)
                        {
                            perror("respond to client error");
                        }
                    }

                    else compare_it(msg, "!close", "/close")
                    {

                        printf("[DEBUG] the client is closing the file\n");
                        // if the client has opened a file then close it
                        if (get_client_by_fd(curr_fd)->isWriting == true)
                        {
                            get_client_by_fd(curr_fd)->isWriting = false;
                            // get the file name he is editing
                            char file_name[SMALL_SIZE];

                            bzero(file_name, SMALL_SIZE);

                            strcpy(file_name, curr_client->file_name);

                            printf("[DEBUG] the file name is %s\n", curr_client->file_name);
                            struct file_stat *curr_file = get_file_by_name(file_name);

                            // print_client_info(get_client_by_fd(curr_fd));
                            curr_file->peers_conn--;
                            print_files();

                            // struct client_stat* curr_client = &curr_file->peers[0];
                            if (curr_file->peers[0].client_id == curr_fd)
                            {
                                curr_file->peers[0].client_id = -1;
                            }
                            else
                            {
                                curr_file->peers[1].client_id = -1;
                            }
                            print_files();
                            if (respond_to_client(curr_fd, "File closed successfully...\n") < 0)
                            {
                                perror("respond to client error");
                            }

                            // log the event
                            char event[SMALL_SIZE];
                            bzero(event, SMALL_SIZE);
                            strcat(event, "User ");
                            char user_fd[10];
                            sprintf(user_fd, "%d", curr_fd);
                            strcat(event, user_fd);
                            strcat(event, " closed the file ");
                            strcat(event, file_name);
                            strcat(event, "\n");
                            log_event(event, log_file_name);
                        }

                        else
                        {
                            if (respond_to_client(curr_fd, "You have not opened a file yet... open a file first\n") < 0)
                            {
                                perror("respond to client error");
                            }
                        }
                    }

                    else compare_it(msg, "edit", "open")
                    {
                        // printf("the message is %s\n", msg);
                        //  if the client already edits a file then he cannot edit another one
                        if (curr_client->isWriting)
                        {
                            char message[100];
                            bzero(message, 100);
                            strcat(message, "You are already editing a file...\n");
                            strcat(message, "Please close the file with ' !close '  before opening another one...\n");
                            if (respond_to_client(curr_fd, message) < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        if ((strcmp(msg_cpy, "edit") == 0 || strcmp(msg_cpy, "open") == 0) || strlen(msg_cpy) == 4)
                        {
                            if (respond_to_client(curr_fd, "Please enter a file name to open/edit... \n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        // client wants to open file
                        char file_name[32];
                        bzero(file_name, 32);

                        // get the name of the file to open

                        strcpy(file_name, msg + 5);

                        strcat(file_name, ".txt");

                        printf("client wants to open %s with len %d \n", file_name, strlen(file_name));

                        chdir(file_folder);

                        bool opened_ok = false;

                        // print_files();
                        for (int i = 0; i < file_struct_indx; i++)
                        {

                            // search the file in the table and mark it
                            if (strcmp(file_table[i].file_name, file_name) == 0) // if the name is present
                            {

                                // mark in the table
                                // TODO if the file is not present

                                if (file_table[i].peers_conn >= 2)
                                {
                                    perror("(open file) lobby already full ...\n");
                                    if (respond_to_client(curr_fd, "(open file)lobby already full ...\n") < 0)
                                    {
                                        perror("respond to client error");
                                    }
                                    continue;
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
                        print_files();
                        // printf("opened ok is %d\n", opened_ok);

                        // if the file is found on the server
                        if (opened_ok)
                        {
                            // mark the client as writing
                            curr_client->isWriting = true;
                            // printf("the file name is %s\n", file_name);
                            curr_client->file_name = file_name;
                            // print_clients();

                            // print_files();

                            // just open the file in append mode
                            FILE *fp;
                            fp = fopen(file_name, "ra");

                            // sent the content of the file to user

                            char file_content[BIG_SIZE];
                            bzero(file_content, BIG_SIZE);
                            fseek(fp, 0, SEEK_END); // get the size of the file
                            long file_size = ftell(fp);
                            rewind(fp);

                            fread(file_content, file_size, 1, fp);

                            printf("[DEBUG] the content is: %s\n", file_content);

                            char message_to_client[2048];
                            bzero(message_to_client, 2048);

                            strcat(message_to_client, "File ");
                            strcat(message_to_client, file_name);
                            strcat(message_to_client, " content is: \n");
                            strcat(message_to_client, file_content);
                            strcat(message_to_client, "\n");
                            strcat(message_to_client, "<everything you write will be appended to the file...>\n");
                            strcat(message_to_client, "<type ' !close '  to close the file>\n");

                            // printf("the messsage is %s\n", message_to_client);
                            if (respond_to_client(curr_fd, message_to_client) < 0)
                            {
                                perror("respond to client error");
                            }
                            char event[100];
                            bzero(event, 100);
                            char user_fd[10];
                            bzero(user_fd, 10);
                            sprintf(user_fd, "%d", curr_fd);
                            strcat(event, "User ");
                            strcat(event, user_fd);
                            strcat(event, " opened file ");
                            strcat(event, file_name);
                            strcat(event, "\n");
                            log_event(event, log_file_name);

                            // fwrite(file_content, 1, strlen(file_content), fp);
                            fclose(fp);
                        }

                        else
                        {
                            // we didnt find the file
                            char response[100];
                            strcat(response, "File with name '");
                            strcat(response, file_name);
                            strcat(response, "' not found\n");
                            if (respond_to_client(curr_fd, response) < 0)
                            {
                                perror("respond to client error");
                            }
                        }
                    }

                    else compare_it(msg, "download", "/down")
                    {
                        if (curr_client->isWriting == true)
                        {
                            if (respond_to_client(curr_fd, "You are writing to a file.. can't execute command unless '!close'\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }
                        // printf("the message is %s\n", msg);
                        printf("client wants to download a file \n");

                        // get the file name
                        char file_name[32];
                        char response[MEDIUM_SIZE];
                        bzero(response, MEDIUM_SIZE);
                        bzero(file_name, 32);

                        strcat(file_name, msg + 9);
                        strcat(file_name, ".txt");

                        printf("[DEBUG] the file name is %s\n", file_name);
                        // see if the file exists on the server
                        bool file_exists = false;
                        for (int i = 0; i < file_struct_indx; i++)
                        {
                            if (strcmp(file_table[i].file_name, file_name) == 0)
                            {
                                file_exists = true;
                                break;
                            }
                        }
                        if (file_exists)
                        {

                            strcat(response, "File with name '");
                            strcat(response, file_name);
                            strcat(response, "' found ... initilizing download \n");

                            if (respond_to_client(curr_fd, response) < 0)
                            {
                                perror("respond to client error");
                            }
                            char event[100];
                            bzero(event, 100);
                            char user_fd[10];
                            bzero(user_fd, 10);
                            sprintf(user_fd, "%d", curr_fd);
                            strcat(event, "User ");
                            strcat(event, user_fd);
                            strcat(event, " wants to download file ");
                            strcat(event, file_name);
                            strcat(event, "\n");
                            log_event(event, log_file_name);
                        }
                        else
                        {
                            // file does not exist

                            strcat(response, "File with name '");
                            strcat(response, file_name);
                            strcat(response, "' not found\n");
                            if (respond_to_client(curr_fd, response) < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        // read 'ready from client'
                        char ready[SMALL_SIZE];
                        bzero(ready, SMALL_SIZE);
                        if (read(curr_fd, ready, SMALL_SIZE) < 0) //<-- read from client
                        {
                            perror("read error");
                        }
                        if (strstr(ready, "ready") != NULL)
                        {
                            printf("[DEBUG] client is ready to receive the file\n");
                        }

                        else
                        {
                            printf("[DEBUG] client is not ready to receive the file\n");
                        }

                        // sent the file to the client
                        char file_content[BIG_SIZE];
                        bzero(file_content, BIG_SIZE);

                        chdir(file_folder);
                        FILE *fp;
                        // printf("the file name is %s and the len is %d \n", file_name, strlen(file_name));
                        fp = fopen(file_name, "r");
                        int res = fseek(fp, 0, SEEK_END); // get the size of the file
                        long file_size = ftell(fp);
                        rewind(fp);
                        // int write_res=  fwrite("this is sparta", 1, strlen("this is sparta"), fp);
                        fread(file_content, file_size, 1, fp);
                        fclose(fp);

                        // printf("file writing res is %d\n",write_res);
                        // printf("seek result is %d\n", res);
                        // printf("seek complete\n");
                        // printf("got here\n");

                        printf("[DEBUG] the content is: %s\n", file_content);
                        if (respond_to_client(curr_fd, file_content) < 0)
                        {
                            perror("respond to client error");
                        }
                    }

                    else compare_it(msg, "seekr", "/skr")
                    {
                        if (get_client_by_fd(curr_fd)->isWriting == false)
                        {
                            if (respond_to_client(curr_fd, "You have not opened a file yet... open a file first\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        printf("[DEBUG] client wants to seek a file to the right\n");
                        // the file the user is currently writing to

                        struct file_stat *curr_file = get_file_by_name(curr_client->file_name);
                        printf("[DEBUG] the file name is %s \n", curr_client->file_name);
                        char file_name[SMALL_SIZE];
                        bzero(file_name, SMALL_SIZE);
                        strcpy(file_name, curr_client->file_name);
                        //printf("the file name is %s \n", file_name);
                        // get the position value
                        char pos[SMALL_SIZE];
                        bzero(pos, SMALL_SIZE);
                        strcat(pos, msg + 6);

                        // if the value is not an integer

                        int pos_val = atoi(pos);

                        int term1 =pos_val + curr_file->pointer_pos;
                        int term2  = curr_file->file_size; 
                        if (term1 > term2)
                        {
                            if (respond_to_client(curr_fd, "You cannot seek to a position greater than the file size\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }
                        

                        printf("[DEBUG] the position value is %d \n", pos_val);

                        // open the file in append mode
                        FILE *fp;
                        int res = chdir(file_folder);
                        //printf("res is %d \n", res);
                        //printf("the current folder is %s \n", getcwd(NULL, 0));
                        
                        fp = fopen(curr_client->file_name, "a");

                        // seek left in file
                        // fseek(fp, pos_val, curr_file->pointer_pos); // get the size of the file
                        // curr_file->pointer_pos = ftell(fp);
                        // seek to the left

                        fseek(fp, curr_file->pointer_pos, SEEK_SET); // move to the current position from the beginning of the file
                        printf("[DEBUG] the current position is %d in file %s \n ", ftell(fp), curr_file->file_name);

                        int seek_res = fseek(fp, pos_val, SEEK_CUR);
                        if (seek_res != 0)
                        {
                            printf("[DEBUG] seek error \n");

                            if (respond_to_client(curr_fd, "Invalid seek value ... ") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        curr_file->pointer_pos = ftell(fp);

                        // long file_size = ftell(fp);
                        // rewind(fp);

                        // int curr_pos = curr_file->pointer_pos;
                        printf("[DEBUG] the current position is %d in file %s \n ", ftell(fp), curr_file->file_name);
                        char response[SMALL_SIZE];
                        bzero(response, SMALL_SIZE);
                        strcat(response, "Current position is : ");
                        sprintf(pos, "%d", curr_file->pointer_pos);
                        strcat(response, pos);
                        strcat(response, "\n");
                        if (respond_to_client(curr_fd, response) < 0)
                        {
                            perror("respond to client error");
                        }

                        char event[SMALL_SIZE];
                        bzero(event, SMALL_SIZE);
                        char user_fd[SMALL_SIZE];
                        bzero(user_fd, SMALL_SIZE);
                        sprintf(user_fd, "%d", curr_fd);
                        strcat(event, user_fd);
                        strcat(event, " ");
                        strcat(event, "seekr");
                        strcat(event, " ");
                        strcat(event, curr_client->file_name);
                        strcat(event, " ");
                        strcat(event, pos);
                        strcat(event, "\n");
                        log_event(event, log_file_name);
                        fclose(fp);
                        // /chdir("..");
                        strcpy(curr_client->file_name, file_name);
                    }

                    else compare_it(msg, "seekl", "/skl")
                    {
                        if (get_client_by_fd(curr_fd)->isWriting == false)
                        {
                            if (respond_to_client(curr_fd, "You have not opened a file yet... open a file first\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        printf("[DEBUG] client wants to seek a file to the left\n");
                        // the file the user is currently writing to

                        struct file_stat *curr_file = get_file_by_name(curr_client->file_name);

                        // get the position value
                        char pos[SMALL_SIZE];
                        bzero(pos, SMALL_SIZE);
                        strcat(pos, msg + 6);

                        // if the value is not an integer

                        int pos_val = atoi(pos);

                        printf("[DEBUG] the position value is %d \n", pos_val);

                        // open the file in append mode
                        FILE *fp;
                        chdir(file_folder);

                        fp = fopen(curr_client->file_name, "a");

                        fseek(fp, curr_file->pointer_pos, SEEK_SET); // move to the current position from the beginning of the file
                        printf("[DEBUG] the current position before is %d in file %s \n ", ftell(fp), curr_file->file_name);

                        int seek_res = fseek(fp, -pos_val, SEEK_CUR);
                        if (seek_res != 0)
                        {
                            printf("[DEBUG] seek error \n");

                            if (respond_to_client(curr_fd, "Invalid seek value ... ") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        curr_file->pointer_pos = ftell(fp);

                        char response[SMALL_SIZE];
                        bzero(response, SMALL_SIZE);
                        strcat(response, "Current position is : ");
                        sprintf(pos, "%d", curr_file->pointer_pos);
                        strcat(response, pos);
                        strcat(response, "\n");
                        if (respond_to_client(curr_fd, response) < 0)
                        {
                            perror("respond to client error");
                        }

                        // read all from the file
                        fclose(fp);
                        fp = fopen(curr_client->file_name, "r");
                        fseek(fp, curr_file->pointer_pos, SEEK_SET); // move to the current position from the beginning of the file
                        char buffer[BIG_SIZE];
                        bzero(buffer, BIG_SIZE);
                        fread(buffer, 1, BIG_SIZE, fp);
                       // printf("[DEBUG] file after seek is %s \n", buffer);
                        //printf("file name is %s \n", curr_client->file_name);
                        // chdir("..");
                    }

                    else compare_it(msg, "list-files", "ls")
                    {
                        if (curr_client->isWriting == true)
                        {
                            if (respond_to_client(curr_fd, "You are writing to a file.. can't execute command unless '!close'\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        // list all the names in the file_table
                        printf("client wants to list files\n");
                        char response[SMALL_SIZE];
                        bzero(response, SMALL_SIZE);

                        strcat(response, "Files in the server:\n");
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
                                    // printf("[DEBUG] name is %s\n", dir->d_name);
                                    strncat(response, dir->d_name, strlen(dir->d_name));
                                    strcat(response, "\n");
                                    // printf(" the respons is %s\n", response);
                                    // write(curr_fd,response,strlen(response));
                                }
                            }
                        }

                        if (strlen(response) == 0)
                            strcpy(response, "No files in the server\n");
                        closedir(d);
                        chdir("..");
                        //

                        if (respond_to_client(curr_fd, response) < 0)
                        {
                            perror("respond to client error");
                        }

                        // write(pipe_ends[1], response, strlen(response));
                    }

                    else compare_it(msg, "file-info", "info file")
                    {

                        // get the info about the file
                        // get the file name
                        char file_name[SMALL_SIZE];
                        bzero(file_name, SMALL_SIZE);
                        strcat(file_name, msg + 10);
                        strcat(file_name, ".txt");
                        // find the file in the file table
                        struct file_stat *curr_file = get_file_by_name(file_name);
                        if (curr_file == NULL)
                        {
                            if (respond_to_client(curr_fd, "File not found") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        // else display the info about the file
                        char response[MEDIUM_SIZE];
                        bzero(response, MEDIUM_SIZE);
                        strcat(response, "File name: ");
                        strcat(response, curr_file->file_name);
                        strcat(response, "\n");
                        strcat(response, "Clients connected: ");
                        char conn[SMALL_SIZE];
                        bzero(conn, SMALL_SIZE);
                        sprintf(conn, "%d", curr_file->peers_conn);
                        strcat(response, conn);
                        strcat(response, "\n");
                        strcat(response, "File size: ");
                        char size[SMALL_SIZE];
                        bzero(size, SMALL_SIZE);
                        // get the size of the file
                        FILE *fp;
                        chdir(file_folder);
                        fp = fopen(curr_file->file_name, "r");
                        fseek(fp, 0, SEEK_END);
                        long file_size = ftell(fp);
                        rewind(fp);
                        sprintf(size, "%ld", file_size);
                        strcat(response, size);
                        strcat(response, "\n");

                        if (respond_to_client(curr_fd, response) < 0)
                        {
                            perror("respond to client error");
                        }
                    }

                    else compare_it(msg, "backspace", "bs")
                    {
                        if (curr_client->isWriting == false)
                        {
                            if (respond_to_client(curr_fd, "You are not writing to a file.. can't execute command\n") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        // print_client_info(curr_client);
                        // print_files();
                        struct file_stat *curr_file = get_file_by_name(curr_client->file_name);

                        printf("curr file name is %s\n", curr_file->file_name);

                        if (curr_file == NULL)
                        {
                            if (respond_to_client(curr_fd, "File not found") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        // get the value
                        char value[SMALL_SIZE];
                        bzero(value, SMALL_SIZE);
                        strcat(value, msg + strlen("backspace "));
                        int val = atoi(value);
                        printf("the value is %d\n", val);

                        printf("[DEBUG] the value is %d\n", val);
                        // int operation = val - 1;
                        // printf("[DEBUG] the operation is %d\n", operation);

                        // curr_file->pointer_pos -= val;
                        //  /print_files();
                        int pos = curr_file->pointer_pos - val;

                        printf("%d\n", pos);
                        if (pos < 0)
                        {
                            // printf("can't backspace more than the beggining of file\n");
                            if (respond_to_client(curr_fd, "Can't backspace more than the beggining of file") < 0)
                            {
                                perror("respond to client error");
                            }
                            continue;
                        }

                        // 121212121212112121 --> backspace 10
                        //  delete value chars from current position from file
                        FILE *fp;
                        chdir(file_folder);
                        fp = fopen(curr_file->file_name, "r+");

                        // go to the beggining of the file
                        fseek(fp, 0, SEEK_SET);
                        char buffer[BIG_SIZE];
                        bzero(buffer, BIG_SIZE);
                        // read until the pointer position
                        fread(buffer, curr_file->pointer_pos - val, 1, fp);

                        printf("the buffer is %s\n", buffer);

                        // open a temp file to store
                        FILE *temp;

                        temp = fopen("temp.txt", "a+");
                        if (temp < 0)
                        {
                            perror("error at opening\n ");
                        }
                        // write the buffer to the temp file
                        fwrite(buffer, curr_file->pointer_pos - val, 1, temp);

                        // seek into fp n chars

                        fseek(fp, val, SEEK_CUR);
                        // printf("the pointer position is %d\n",ftell(fp));
                        // //read the rest of the file
                        bzero(buffer, BIG_SIZE);
                        fread(buffer, curr_file->file_size - ftell(fp), 1, fp);
                        // printf("the second buffer is %s\n", buffer);

                        // //write the rest of the file to the temp file
                        fwrite(buffer, strlen(buffer), 1, temp);
                        // //close the files
                        fclose(fp);
                        fclose(temp);
                        // rename the temp file to the original file
                        rename("temp.txt", curr_file->file_name);
                        curr_file->pointer_pos -= val;
                        curr_file->file_size -= val;
                        char file_name[SMALL_SIZE];
                        strcpy(file_name, curr_file->file_name);
                        // fseek(fp, curr_file->pointer_pos, SEEK_SET);
                        //  int i;
                        //  for (i = 0; i < val; i++)
                        //  {
                        //      fputc(' ', fp);
                        //  }

                        // fclose(fp);
                        // // chdir("..");

                        // update the pointer position
                        // curr_file->pointer_pos -= val;
                        // printf("the pointer position is %d\n", curr_file->pointer_pos);

                        // send the new file content to client
                        char response[BIG_SIZE];
                        bzero(response, BIG_SIZE);
                        strcat(response, "File content:\n");
                        FILE *fp2;
                        // chdir(file_folder);
                        fp2 = fopen(curr_file->file_name, "r");
                        fseek(fp2, 0, SEEK_END);
                        long file_size = ftell(fp2);
                        rewind(fp2);
                        char file_content[BIG_SIZE];
                        bzero(file_content, BIG_SIZE);
                        fread(file_content, 1, file_size, fp2);
                        strcat(response, file_content);
                        fclose(fp2);
                        chdir("..");
                        if (respond_to_client(curr_fd, response) < 0)
                        {
                            perror("respond to client error");
                        }
                        char event[SMALL_SIZE];
                        bzero(event, SMALL_SIZE);
                        strcat(event, "backspace ");
                        strcat(event, value);
                        strcat(event, "\n");
                        log_event(event, log_file_name);
                        // continue;
                        strcpy(curr_client->file_name, file_name);
                        // printf("the file name after backspace is %s\n", curr_client->file_name);
                        //printf("the file name after backspace is %s\n", curr_client->file_name);
                    }
                    // if the user is writing to a file just append to it and the dispplay it
                    else if (curr_client->isWriting || curr_client->isWriting && strcmp(msg, "newline") == 0)
                    {
                        chdir(file_folder);
                        printf("the user is writing to a file\n");
                        // get the name of the file he is writing to
                        // print_client_info(curr_client);
                        char file_name[SMALL_SIZE];
                        bzero(file_name, SMALL_SIZE);

                        strcpy(file_name, curr_client->file_name);
                        printf("[DEBUG] the file name he is editing is %s\n", curr_client->file_name);

                        if (strcmp(msg, "newline") == 0)
                        {
                            bzero(msg, BIG_SIZE);
                            strcpy(msg_cpy, "\n");
                        }

                        // append the message to the file at the correct position

                        FILE *fp;
                        fp = fopen(file_name, "r");
                        if (fp == NULL)
                        {
                            perror("fopen error");
                            exit(1);
                        }

                        printf("[DEBUG] the message for append is %s\n", msg_cpy);
                        // read all from file

                        struct file_stat *curr_file = get_file_by_name(file_name);

                        char buffer[BIG_SIZE];
                        bzero(buffer, BIG_SIZE);

                        printf("the pointer pos is %d\n", curr_file->pointer_pos);
                        fread(buffer, 1, curr_file->pointer_pos, fp);
                        printf("the buffer 1 is %s\n", buffer);

                        // // go to the correct position and insert there
                        FILE *temp = fopen("temp.txt", "a+");

                        // // write the buffer to the temp file
                        fwrite(buffer, 1, curr_file->pointer_pos, temp);
                        // // append the message
                        fwrite(msg_cpy, 1, strlen(msg_cpy), temp); // 1212 12121221
                        bzero(buffer, BIG_SIZE);

                        // //read all from temp
                        fseek(fp, curr_file->pointer_pos, SEEK_SET); // get the size of the file

                        fread(buffer, 1, BIG_SIZE, fp);
                        printf("the buffer is %s\n", buffer);
                        // write to the file

                        fwrite(buffer, 1, strlen(buffer), temp);

                        curr_file->pointer_pos += strlen(msg_cpy); // move the cursor to the end of the file
                        curr_file->file_size += strlen(msg_cpy);

                        // fwrite(msg_cpy, 1, strlen(msg_cpy), fp);
                        fclose(fp);
                        fclose(temp);

                        // rename the temp
                        rename("temp.txt", file_name);

                        // get the content of the newly edited file
                        char file_content[BIG_SIZE];
                        bzero(file_content, BIG_SIZE);

                        fp = fopen(file_name, "ra");
                        fseek(fp, 0, SEEK_END); // get the size of the file
                        long file_size = ftell(fp);
                        // printf("the file size is %ld\n", file_size);
                        rewind(fp);

                        fread(file_content, file_size, 1, fp);
                        fclose(fp);

                        // if uncommented the server will crash :)

                        //     char event[MEDIUM_SIZE];
                        //     bzero(event, MEDIUM_SIZE);

                        //     strcat(event, "user: ");
                        //     printf()
                        //     char user_name[SMALL_SIZE];
                        //     bzero(user_name, SMALL_SIZE);

                        //     //sprintf(user_name, "%d", curr_client->client_id);
                        //    // strcat(event, user_name);

                        //     strcat(event, " write: ");
                        //     strcat(event, msg_cpy);
                        //     strcat(event, " to file: ");
                        //     strcat(event, curr_client->file_name);
                        //     strcat(event, " \n");
                        //     log_event(event, log_file_name);

                        if (respond_to_client(curr_fd, file_content) < 0)
                        {
                            perror("respond to client error");
                        }
                        // printf("[DEBUG] the file name he is editing is %s and the message is %s\n", curr_client->file_name, msg_cpy);
                    }
                    // if the msg didnt match any of the commands then send an error message
                    else if (!compare_it_funct(msg, "login", "/l"))
                    {

                        if (respond_to_client(curr_fd, "Invalid command.. please try 'help' \n") < 0)
                        {
                            perror("respond to client error");
                        }
                    }
                }
            }
        }
    }

    char event_log[SMALL_SIZE];
    bzero(event_log, SMALL_SIZE);
    strcat(event_log, "Server stopped at ");
    char time_str[SMALL_SIZE];
    bzero(time_str, SMALL_SIZE);
    time_t t1 = time(NULL);
    struct tm tm1 = *localtime(&t);
    sprintf(time_str, "%d-%d-%d %d:%d:%d", tm1.tm_year + 1900, tm1.tm_mon + 1, tm1.tm_mday, tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
    strcat(event_log, time_str);
    strcat(event_log, "\n");
    log_event(event_log, log_file_name);
}
