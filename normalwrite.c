#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <linux/kernel.h>
#include <sys/syscall.h>

#define BUFFER_LENGTH 256
#define WRITE_CRYPT 385

void concat(int n_arg, char *argv[], char *string);

int main(int argc,char *argv[]){

   char message[BUFFER_LENGTH] = "";
   int ret, fd;

   concat(argc,argv,message);

   // Executa abre o arquivo
   fd = open("testfile.txt", O_WRONLY | O_CREAT | O_TRUNC,0666);
   if (fd < 0){
      perror("Falha ao abrir o arquivo...");
      return errno;
   }

   ret = write(fd,message,strlen(message));// Realiza chamada de sistema
   if (ret < 0){
      perror("Falha escrever no arquivo.");
      return errno;
   }

   printf("\n -Fim do programa!-\n");
   printf("> Foram escritos %d bytes no arquivo!\n\n",ret);

}

// Transforma os argumentos a partir do terceiro em uma string continua
void concat(int n_arg, char *argv[], char *string){

   int tam = 0;
   int i = 1;

   while(i < n_arg){
	strcat(string + tam,argv[i]);

	if(argv[i+1] != NULL)
	   strcat(string + tam," ");

	tam = strlen(argv[i]) + 1;
	i++;
   }
}
