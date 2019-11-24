#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <linux/kernel.h>
#include <sys/syscall.h>

#define BUFFER_LENGTH 256
#define READ_CRYPT 386

int main(int argc,char *argv[]){

   char message[BUFFER_LENGTH] = "";
   int ret, fd;

   // Abre o arquivo
   fd = open("testfile.txt", O_RDONLY);
   if (fd < 0){
      perror("Falha ao abrir o arquivo...");
      return errno;
   }

   ret = syscall(READ_CRYPT,fd,message,256);// Realiza chamada de sistema
   if (ret < 0){
      perror("Falha ler ao arquivo.");
      return errno;
   }

   printf("\n -Fim do programa!-\n");
   printf("> Mensagem lida: %s\n",message);
   printf("> Foram lidos %d bytes cifrados do arquivo!\n\n",ret);

}
