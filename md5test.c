#include<stdio.h>
#include "md5.h"

//To demonstrate md5:

//To compile:
// gcc -o md5test md5.c md5test.c
#define TEST_BUFFER_SIZE 30
int main(int argc, char** argv){
	md5_state_t ms;
	md5_init(&ms);
	char data[] = "a";
	md5_append(&ms,(md5_byte_t *) data,13);
	char text_digest[TEST_BUFFER_SIZE] = {0};
	int chars =	md5_finish_text(&ms,text_digest,0);
	text_digest[chars] = '\0';
	printf("Message:\n");
	printf("%s\n",(char *) text_digest);
	return 0;
}
