#include<stdio.h>
#include "md5.h"
#include <unistd.h>
//To demonstrate md5:
//To compile:
// gcc -o md5test md5.c md5test.c
#define READ_SIZE 128

int compute_Checksum(char * filename, char* digest){
   char buffer[READ_SIZE+1];
   md5_state_t ms;
   md5_init(&ms);
   int amt;
   int fd = open(filename,0);
   for(;;){
      amt = (int) read(fd,buffer,READ_SIZE);
      buffer[amt] = '\0';
      if(amt == 0){
         amt = md5_finish_text(&ms,digest,0);
         digest[amt] = '\0';
         return amt;
      }
      md5_append(&ms,(md5_byte_t *) buffer,amt);
   }
}

int main(int argc, char** argv){
	char text_digest[MD5_TEXT_DIGEST_MAX_SIZE+1];
	int chars =	compute_Checksum(argv[1],text_digest);
	printf("Digest: %s\n",text_digest);
	return 0;
}
