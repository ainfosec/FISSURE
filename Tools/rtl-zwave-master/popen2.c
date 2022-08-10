#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

 /*  Pre:  The  shell  command  that  should  be  executed  is  passed  as  a  parameter.
   *            Values  of  0  for  p_fd_in  or  p_fd_out  indicates  shell  command  doesn't
   *            use  stin  or  stdout  respectively,  so  they  should  be  closed.
   *  Post:  Makes  accessible  both  the  standard  input  and  output  of  the  shell  
   *              process  it  creates.
   *              Two  pipes  are  created:  one  provides  standard  input  for  the  shell  
   *              commmand,  and  the  other  for  passing  back  its  standard  output.
   *              The  pipe  file  descriptors  for  the  caller  to  use  are  pointed  to  by  
   *              p_fd_in  and  p_fd_out.
   */      
 pid_t popen2(const char *shell_cmd, int *p_fd_in, int *p_fd_out)
 {
    //CREATING  TWO  PIPES:
  int fds_processInput[2];  //pipe  for  process  input
  int fds_processOutput[2]; //pipe  for  process  output
   
   if(pipe(fds_processInput) != 0) //create  process  input  pipe
     {
       perror( "pipe (process input) failed\n" );
       exit(1);
     }
   
   if(pipe(fds_processOutput) != 0) //create  process  output  pipe
     {
       perror( "pipe (process output) failed\n");
       exit(1);
     }
   
   //FORKING  A  CHILD  PROCESS:
   pid_t pid;
   if((pid = fork()) < 0)
     {
       perror( "fork failed\n" );
       exit(2);
     }
   
  //CONNECT  THE  CORRECT  PIPE  ENDS  IN  THE  CHILD:
   if(pid == 0)  //child  process
     {
       //for  process  input  pipe:
       close(fds_processInput[1]);   //close  output
       dup2(fds_processInput[0], 0); //close  fd  0,  fd  0  =  fds_processInput[0]
       
       //for  process  output  pipe:
       close(fds_processOutput[0]);   //close  input
       dup2(fds_processOutput[1], 1); //close  fd  1,  fd  1  =  fds_processOutput[1]
       
       execl("/bin/sh", "sh", "-c", shell_cmd, 0 );        
     }
   else  //parent  process
     {
       //for  process  input  pipe:
       close(fds_processInput[0]);   //close  input
       
       //for  process  output  pipe:
       close(fds_processOutput[1]);   //close  output
 
       if(p_fd_in == 0)
     close(fds_processInput[1]);
       else
     *p_fd_in = fds_processInput[1];
       
       if(p_fd_out == 0)
     close(fds_processOutput[0]);
       else
     *p_fd_out = fds_processOutput[0];
 
     }
   return pid; 
 }


