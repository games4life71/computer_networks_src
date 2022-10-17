#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <utmp.h>
#include <sys/socket.h>

#define fifo_file_write "my_fifo2.txt"
#define fifo_file_read "my_fifo.txt"
#define MAX_READ_BUFF 100
#define read_end 0
#define write_end 1

#define MAX_RETRIES_TO_CONNECT 15

#define compare_it(STR1, STR2, STR3) if (strstr(STR1, STR2) != NULL || strstr(STR1, STR3) != NULL)
int main()
{
  unsigned int counts = 0;
  bool is_logged = false;

  if (access(fifo_file_read, F_OK) != 0)
  {
    // file doesnt exists
    mkfifo(fifo_file_read, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
  }

  if (access(fifo_file_write, F_OK) != 0)
  {

    mkfifo(fifo_file_write, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
    
  }

  while (1)
  {
    int fd_read = open(fifo_file_read, O_RDONLY );
    int fd_write = open(fifo_file_write, O_WRONLY);

    // while there is a connection
    char curr_command[200];
    char curr_response[200];

    int read_status = read(fd_read, curr_response, MAX_READ_BUFF);
    
    if (counts == MAX_RETRIES_TO_CONNECT)
    {

      printf("[WARNING]: Server shutting down ... no clients\n");
      exit(3); // client failed to connect
    }
    if (read_status == 0)
    {
      printf("[WARNING]: Client disconnected , waiting ...\n");
      counts++;
     // sleep(5);
      // exit(1);
    }
    else
    {

      curr_response[read_status] = NULL;

      if (strcmp("quit", curr_response) == 0)
      {

        printf("Quit command from client...\n");
        exit(0);
      }

      printf("[DEBUG INFO] %s\n", curr_response);

      // login command

      compare_it(curr_response, "get-logged-users :", "/lu")
      {

        if (!is_logged)
        {
          write(fd_write, "[ERROR]User not logged in ..command failed !\n", strlen("[ERROR]User not logged in ..command failed !\n"));
        }

        else
        {
          // user is logged in

          int usr_pipe[2];
          size_t create_pipe = pipe(usr_pipe);
          if (create_pipe < 0)
          {

            perror("[ERROR]:");
          }

          pid_t pid = fork();

          if (pid == 0)
          {
            // child part
            close(usr_pipe[read_end]);
            struct utmp *data;
            data = getutent();

            char temp[UT_HOSTSIZE + UT_NAMESIZE];

            while (data != NULL)
            {
              char temp[UT_HOSTSIZE + UT_NAMESIZE * 2];
              char temp1[UT_NAMESIZE];

              strncpy(temp, data->ut_host, UT_HOSTSIZE);
              strncpy(temp1, data->ut_user, UT_NAMESIZE);
              strcat(temp, "\n");
              strncat(temp, data->ut_user, UT_NAMESIZE);

              int tv_usec = data->ut_tv.tv_sec;
              int len = sprintf(temp1, "%d", tv_usec);
              strcat(temp, "\n");
              strncat(temp, temp1, len);

              data = getutent();

              write(usr_pipe[write_end], temp, strlen(temp));
            }

            exit(0);
          }

          else if (pid > 0)
          {
            // parent
            wait(NULL);

            close(usr_pipe[write_end]);
            char data[UT_HOSTSIZE + UT_NAMESIZE];

            ssize_t read_data;
            while (read_data = read(usr_pipe[read_end], data, UT_HOSTSIZE + UT_NAMESIZE * 2) != 0)
            {

              printf("%s\n", data);
            }
            write(fd_write, data, strlen(data));
          }

          else
          {

            // errro on create

            perror("[ERROR] Process creation failed !\n");
          }
        }

        continue;
      }

      else compare_it(curr_response, "get-proc-info :", "/gp")
      {

        if (!is_logged)
        {
          write(fd_write, "[ERROR]User not logged in ..command failed !\n", strlen("[ERROR]User not logged in ..command failed !\n"));
        }

        // construct the full path

        char pid_no[10];
        if (strstr(curr_response, "get-proc-info :") != NULL)
          strcpy(pid_no, strstr(curr_response, ":") + 2);

        else
        {
          strcpy(pid_no, curr_response + 4);
        }

        pid_no[strlen(pid_no) - 1] = '\0';
        char path[100];
        path[0] = '\0';
        strcat(path, "/proc/");
        strcat(path, pid_no);
        strcat(path, "/status\0");
        printf("[DEBUG INFO] : the path is %s\n", path);
#define MAX_BUFFER_LENGTH 512

        int proc_pipe[2];
        static const int parentsocket = 0;
        static const int childsocket = 1;
        int return_stat = socketpair(PF_LOCAL, SOCK_STREAM, 0, proc_pipe);

        // size_t pipe_status = pipe(proc_pipe);

        if (return_stat < 0)
        {
          perror("[ERROR]: ");
        }

        pid_t pid = fork();

        if (pid == 0)
        {
          // child playground
         
          FILE *fp = fopen(path, "r");
          char *line = NULL;
          size_t len = 0;
          ssize_t read;

          if (fp == NULL)
          {
            exit(EXIT_FAILURE);
          }

          char message[MAX_BUFFER_LENGTH];
          message[0] = '\0';
          close(proc_pipe[parentsocket]);

          while ((read = getline(&line, &len, fp)) != -1)
          {
            if (strstr(line, "Name") != 0)
            {
              strncat(message, line, strlen(line));
              strcat(message, "\n");
            }

            else if (strstr(line, "State") != 0)
            {
              strncat(message, line, strlen(line));
              strcat(message, "\n");
            }
            else if (strstr(line, "PPid") != 0)
            {
              strncat(message, line, strlen(line));
              strcat(message, "\n");
            }
            else if (strstr(line, "Uid") != 0)
            {
              strncat(message, line, strlen(line));
              strcat(message, "\n");
            }
          }

          write(proc_pipe[childsocket], message, strlen(message));
          exit(0);
        }

        else if (pid > 0)
        {

          // parent's space
          wait(NULL);
          char buffer[MAX_BUFFER_LENGTH];
          close(proc_pipe[childsocket]);
          read(proc_pipe[parentsocket], buffer, MAX_BUFFER_LENGTH);

          write(fd_write, buffer, strlen(buffer));
        }

        else
        {

          perror("[ERROR]:");
        }

        continue;
      }

      else compare_it(curr_response, "login :", "/l")
      {
       
        if (is_logged == true)
        {
          write(fd_write, "[ERROR]: User already logged-in ! \n", strlen("[ERROR]: User already logged-in ! \n"));
        }

        else
        {
          int login_pipe[2];
          size_t create_pipe = pipe(login_pipe);

          if (create_pipe < 0)
          {
            perror("[ERROR]: ");
          }

          pid_t pid = fork();
          if (pid == 0)
          {

            //child
            // check for username in the 'usernames.txt' file

            FILE *fd = fopen("usernames.txt", "r");
            close(login_pipe[read_end]);
            char *line = NULL;
            size_t len = 0;
            ssize_t read;

            if (fd == NULL)
              exit(EXIT_FAILURE);

            while ((read = getline(&line, &len, fd)) != -1)
            {
              
              if (strstr(curr_response, line) != NULL)
              {

                printf("[DEBUG INFO]: User %s logged in succesfully !\n", line);

                is_logged = true;
                int write_res = write(login_pipe[write_end], "Logged with succes!\n", strlen("Logged with succes!\n"));
                break;
              }
            }

            if (is_logged == false)
            {
              // username didnt match any entries
              write(login_pipe[write_end], "Logged failed !\n", strlen("Logged failed !\n"));
            }

            fclose(fd);
            exit(0); // YOUR JOB IS DONE !
          }

          else
          {

            // parent

            wait(NULL); // wait for child to finish

            close(login_pipe[write_end]); // close to writing
            // read from children pipe
            char log_result[20];
            ssize_t read_res = read(login_pipe[read_end], log_result, 80);
            
            if (strstr(log_result, "Logged with succes!\n") != NULL)
              is_logged = true;

            else
              is_logged = false; // already on 'false'

            int write_status = write(fd_write, log_result, strlen(log_result));
          }
        }
      }

      else compare_it(curr_response, "logout", "/exit")
      {

        // disconnect user
        is_logged = false;
        write(fd_write, "Logout command issued\n", strlen("Logout command issued\n"));
      }
      else compare_it(curr_response, "add-user : ", "/au ")
      {
        // add a new user to the server

        int add_pipe[2];

        size_t create_pipe = pipe(add_pipe);

        if (create_pipe < 0)
        {
          perror("[ERROR]:");
        }

        pid_t pid = fork();

        if (pid == 0)
        {
          // child part
          FILE *fp = fopen("usernames.txt", "a");
          close(add_pipe[read_end]);

          // parse the username

          char new_username[MAX_READ_BUFF];

          if (strstr(curr_response, "add-user : ") != NULL)
          {
            strcpy(new_username, strstr(curr_response, ":") - 1);
            printf("[DEBUG]: the new username is %s\n", new_username);
          }

          else
          {
            strcpy(new_username, curr_response + 3);
            printf("[DEBUG]: the new username is %s\n", new_username);
          }
          fwrite(new_username, 0, strlen(new_username), fp);
          fclose(fp);
          write(add_pipe[write_end], "User succesfully added ! \n", strlen("User succesfully added ! \n"));
          exit(0);
        }

        else if (pid > 0)
        {

          // parent

          wait(NULL);
          char buff[MAX_READ_BUFF];
          close(add_pipe[write_end]);
          read(add_pipe[read_end], buff, MAX_READ_BUFF);

          write(fd_write, buff, strlen(buff));
        }

        else
        {
          perror("[ERROR]:");
        }

      }

      else compare_it(curr_response, "help", "/h")
      {

        write(fd_write, "'login :[ user-name]','/l [user-name] ' \n 'get-proc-info [PID]' ,'/gp [PID]' \n , 'get-logged-users' ,'/lu' \n  'logout', '/exit' \n ,'quit' ,'/q' \n ", strlen("'login :[ user-name]','/l [user-name] ' \n 'get-proc-info [PID]' ,'/gp [PID]' \n , 'get-logged-users' ,'/lu' \n  'logout', '/exit' \n ,'quit' ,'/q' \n "));
      }
      else
      {
        write(fd_write, "Unrecognized command \n Use 'help' or '/h' command to display all commands available..\n", strlen("Unrecognized command \n Use 'help' or '/h' command to display all commands available..\n"));
      }

      close(fd_read);
    }
  }
}