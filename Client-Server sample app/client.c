#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <utmp.h>

#define fifo_file_read "my_fifo2.txt"
#define fifo_file_write "my_fifo.txt"
#define MAX_READ_BUFF 300
int main()
{

 
  // //create the FIFO files
  // int create_status_read;
  // int create_status_write;

  // check for operation failure
  if (access(fifo_file_read, F_OK) != 0)
  {
    // file doesnt exists
    mkfifo(fifo_file_read, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
    // printf("%s", "Failed to create fifo read ...already existing\n");
  }

  if (access(fifo_file_write, F_OK) != 0)
  {

    mkfifo(fifo_file_write, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
    // printf("%s", "Failed to create fifo write  ...already existing\n");
  }

  // open the FIFO files
    int fd_write = open(fifo_file_write, O_WRONLY);
    int fd_read = open(fifo_file_read, O_RDONLY);
  
  while (1)
  {
    // while there is a connection `
     char curr_command[200];
     char curr_response[200];

    //fgets(curr_command, 80, stdin);
    curr_command[0] = '\0';
   int read_length_stdin = read(0,curr_command,80);
   curr_command[read_length_stdin]=NULL;
  //printf("lenght of commands : %d\n", strlen(curr_command));
   
   if(strcmp("quit\n",curr_command) == 0 || strcmp("QUIT\n",curr_command) == 0 || strcmp("/q\n",curr_command) == 0 ) 
   
   {
    printf("Sending 'quit' signal to server ... \n");
    write(fd_write,"quit",strlen("quit"));
    
    exit(0); //exit without errors 

   }

   

   int write_length =  write(fd_write, curr_command, strlen(curr_command));
   //printf(" written :%s\n", curr_command);
    
    if(write_length<0)
    {
      perror("[ERROR]:");

    }

    // and now read
    int read_length = read(fd_read, curr_response,MAX_READ_BUFF);
    if(read_length<0)
    {
     perror("[ERROR]:");

    }
    
    //printf("read : %d\n",read_status);
     curr_response[read_length]=NULL;

     printf("[Server]: %s\n", curr_response);


    // if(curr_command)
    // free(curr_command);

    // if(curr_response)
    // free(curr_response);
    
  }
    close(fd_read);
    close(fd_write);
}