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
#include <signal.h>
#include <sys/stat.h>

// #include <gtk/gtk.h>

#define SMALL_SIZE 256
#define MEDIUM_SIZE 1024
#define BIG_SIZE 2048
#define DOWNLOADS_DIR "downloads"
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

int port;
int global_sd;
void encode_message(char *msg, char encoded[])
{

    // printf("%s\n",msg);
    char encoded_msg[BIG_SIZE];
    char length[9];
    bzero(length, 9);

    if(strlen(msg) == 0){
        strcpy(encoded, "0$");
        return;
    }
    sprintf(length, "%d", strlen(msg) - 1); // get the len of the message
    // printf("%s\n",length);
    // strcpy(encoded,length);
    strcat(encoded, length); // append it to encoded msg
    strcat(encoded, "$");    // append  $
    strcat(encoded, msg);    // append the message
    return;
}

int signal_callback_handler(int signum)
{

    char encoded[256];
    bzero(encoded, 256);
    encode_message("exit", encoded);

    printf("the message is %s\n", encoded);
    // Terminate program
    write(global_sd, encoded, strlen(encoded));
    printf("exit message sent ");
    close(global_sd);
    exit(1); // inttreupt
}

// //handler for activate
// static void app_activate(GApplication *app, gpointer user_data)
// {
//     GtkWidget *win;
//     GtkWidget *textview;

//     textview = gtk_text_view_new();
//     win = gtk_window_new();

//     gtk_window_set_child(GTK_WINDOW(win), textview);
//     gtk_window_set_application(GTK_WINDOW(win), GTK_APPLICATION(app)); //connect to app process
//     gtk_window_set_title(GTK_WINDOW(win), "Text editor");
//     gtk_window_present(GTK_WINDOW(win));
// }

int decode_messaje(char *raw_msg, char *msg)
{

    // ex: 4$exit
    char length[8];
    strncpy(length, raw_msg, strchr(raw_msg, '$') - raw_msg);
    // printf("%s\n", length);

    int length_int = atoi(length);
    if(length_int == 0){
        return 0;
    }   
    char *p = strchr(raw_msg, '$') + 1;
    // printf("%s\n", p);
    // bzero(raw_msg,strlen(raw_msg));
    strcpy(msg, p);
    // printf("%s,%d\n", raw_msg, length_int);
    return length_int;
}

int main()
{

    //  GtkApplication *app;
    // int stat;

    // // window = gtk_application_window_new(app);
    // app = gtk_application_new("com.github.ToshioCP.pr1", G_APPLICATION_FLAGS_NONE);

    // g_signal_connect(app, "activate", G_CALLBACK(app_activate), NULL); // handler for the activate signal

    // // gtk_window_present(GTK_WINDOW(window));
    // stat = g_application_run(G_APPLICATION(app), argc, argv);
    // g_object_unref(app);
    // return stat;

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
    // set global_sd so we can kill il

    global_sd = sd;
    // connect to server
    // bzero(msg,100);

    if (connect(sd, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        perror("connect() error");
        exit(-1);
    }

    char msg[BIG_SIZE];

    // strcpy(msg, "cf");
    while (1)
    {

        signal(SIGINT, signal_callback_handler);
        bzero(msg, BIG_SIZE);
        // printf("Enter message: ");

        int read_length_stdin = read(0, msg, BIG_SIZE);
        // printf("the message is %s\n", msg);
        if (read_length_stdin < 0)
        {
            perror("read error");
        }
        // msg[read_length_stdin]=NULL;

        char sentmsg[BIG_SIZE]; // the message that will pe sent according to the protocol
        bzero(sentmsg, BIG_SIZE);

        // copy of the message
        char msgcopy[BIG_SIZE];
        bzero(msgcopy, BIG_SIZE);
        strcpy(msgcopy, msg);
        msg[strcspn(msg, "\n")] = NULL;

        // printf("the message  copy is %s and the msg is %s\n", msgcopy,msg);
        // compare it to download message
        compare_it(msgcopy, "download", "/down")
        {

            // get the file name
            // printf("client wants to download a file \n");

            // get the file name
            char file_name[MEDIUM_SIZE];
            bzero(file_name, MEDIUM_SIZE);
            // printf("the msg is %s\n", msg);
            strncat(file_name, msg + strlen("download"), strlen(msg) - 1);
            strcat(file_name, ".txt");

            // /printf("the file name is %s\n", file_name);

            // wait for response from server
            // write the message to the server
            // encode the message
            encode_message(msg, sentmsg);

            write(sd, sentmsg, strlen(sentmsg));
            printf("download message sent \n");

            char response[BIG_SIZE];
            bzero(response, BIG_SIZE);
            int read_length = read(sd, response, BIG_SIZE); // read response from server
            if (read_length < 0)
            {
                perror("read error");
            }
            // printf("%s\n", response);
            //  if the file is not present in the server or the user is not logged in
             char response_decoded[BIG_SIZE];
            bzero(response_decoded, BIG_SIZE);
            int len = decode_messaje(response, response_decoded);

            // /printf("len is %d and read length is %d\n", len, read_length);
            if (len != strlen(response_decoded))
            {
                perror("error in decoding or writing");
            }
            
            printf("[SERVER] %s\n", response_decoded);
            if (strstr(response, "not logged in") != NULL || strstr(response, "not found") != NULL)
            {
                //printf("ba nu a gasito sa mor eu !\n");
                continue;
            }


            //sent ready to server
            char ready[SMALL_SIZE];
            bzero(ready, SMALL_SIZE);
            strcpy(ready, "ready");
            bzero(sentmsg, BIG_SIZE);
            encode_message(ready, sentmsg);
            write(sd, sentmsg, strlen(sentmsg));  // ---> to server 
            printf("[DEBUG] ready message sent \n");

            //now receive the file from server 


            char file_content[BIG_SIZE];
            bzero(file_content, BIG_SIZE);
            read_length = read(sd, file_content, BIG_SIZE); // read response from server
            printf("read length is %d\n", read_length);
            if (read_length < 0)
            {
                perror("read error");
            }
            printf("[DEBUG] file content received with the content: \n %s \n",file_content);

            // go to downloads folder and create the file
            // create a folder if it doesnt exist
            int res = mkdir(DOWNLOADS_DIR, 0777);

            if (res == -1 && strstr(strerror(errno), "File exists") != NULL)
            {
                printf("[DEBUG] the folder already exists\n");
            }

            chdir(DOWNLOADS_DIR);

            // create the file
            FILE *fp = fopen(file_name, "w");
            //write the content to the file
            //decode the message
            char file_content_decoded[BIG_SIZE];
            bzero(file_content_decoded, BIG_SIZE);
            int len_file = decode_messaje(file_content, file_content_decoded);
            if (len_file != strlen(file_content_decoded))
            {
                perror("error in decoding or writing");
            }
            fwrite(file_content_decoded, 1, strlen(file_content_decoded), fp);
            fclose(fp);

            chdir("..");
            // read another response
            //bzero(response, BIG_SIZE);
            // /read_length = read(sd, response, BIG_SIZE); // read response from server if the file is found or not

            // write confirmation to server
            // char confirmation[BIG_SIZE];
            // bzero(confirmation, BIG_SIZE);
            // strcpy(confirmation, "file downloaded correctly...");
            // bzero(sentmsg, BIG_SIZE);
            // encode_message(confirmation, sentmsg);
            // write(sd, sentmsg, strlen(sentmsg));
        }

        else
        {   
            if(strcmp(msg,"\n") == 0 || strlen(msg) == 0 ){
                printf("empty message\n");
                //printf("empty message\n");
                //dont encode it
                //strcpy(sentmsg, msg); 
                strcat(sentmsg, "\n");
                //continue;
            }

           
            //the message isnt empty so we encode it 
            encode_message(msg, sentmsg);
            
            printf("the sent message is %s\n", sentmsg);

            char length[8];
            bzero(length, 8);

            sprintf(length, "%d", read_length_stdin);
            // printf("the message is %s and the length is %s\n", sentmsg, length);
            if (write(sd, sentmsg, read_length_stdin + strlen(length)) == -1)
            {
                perror("write() error");
                exit(-1);
            }
            printf("[DEBUG] message %s sent\n", sentmsg);

            char read_srv[BIG_SIZE];
            bzero(read_srv, BIG_SIZE);

            size_t read_len = read(sd, read_srv, BIG_SIZE);

            read_srv[read_len] = NULL;

            if (read_len == -1)
            {
                perror("read msg");
            }

            // decode the message from the server
           // printf("[DEBUG] received message is %s\n", read_srv);
            char msg_sv[BIG_SIZE]; // decoded message from server

            bzero(msg_sv, BIG_SIZE);
            int msg_len_sv = decode_messaje(read_srv, msg_sv);

            // printf(" msg  after decode is %s\n",read_srv);
            // printf(" msg  len after decode is %d\n",strlen(read_srv));

            if (msg_len_sv != strlen(msg_sv))
            {
                perror("read not complete");
            }

            else
                printf("[SERVER] %s\n", msg_sv);
        }
    }
    close(sd);
}