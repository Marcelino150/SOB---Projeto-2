#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/unistd.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#define	 W_CRYPTOKEY "0123456789ABCDEF"

struct writetcrypt_result {
    struct completion completion;
    int err;
}wa;

struct write_skcipher_def {
    struct scatterlist source;
    struct scatterlist destination;
    struct crypto_skcipher *tfm;
    struct skcipher_request *request;
    struct writetcrypt_result result;
}wb;

static unsigned int w_skcipher_encdec(struct write_skcipher_def *sk, int enc)
{
    int rc = 0;

    if (enc){
        rc = crypto_skcipher_encrypt(sk->request); // Cifra a requisição
    }
    else{
        rc = crypto_skcipher_decrypt(sk->request); // Decifra a requisição
    }

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:;
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt retornou %d como resultado %d\n", rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}

asmlinkage extern ssize_t write_crypt(int fd, const void *buf, size_t nbytes){

   struct write_skcipher_def sk;
   struct crypto_skcipher *skcipher = NULL;
   struct skcipher_request *request = NULL;
   int ret = 0;
   int i,j;
   int cipherlen;              // Tam da mensagem a ser cifrada (multiplo de 16)
   int lenght;

   char *plaintext = NULL;     // Buffer para a mensagem a ser cifrada 
   char *ciphertext = NULL;    // Buffer para a mensagem cifrada
   char originalText[256];

   char *buffer = NULL;	       // Buffer para receber a conversão em HEX
   struct fd f;

   loff_t pos = 0;

   if(strlen((char*)buf) > 256)
	return -1;

   strcpy(originalText,(char*)buf);

   // Aloca skcipher em modo de cifragem ecb
   skcipher = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);
   if (IS_ERR(skcipher)) {
	pr_info("skcipher nao pode ser alocado\n");
	return -1;
   }
   printk(KERN_INFO "CRYPTO: Skcipher alocado\n");

   // Aloca requisição de criptografia
   request = skcipher_request_alloc(skcipher, GFP_KERNEL);
   if (!request) {
	pr_info("skcipher request nao pode ser alocado\n");
	crypto_free_skcipher(skcipher);
	return -1;							
   }
   printk(KERN_INFO "CRYPTO: request alocada\n");

   // Seta chave criptográfica para o skcipher em modo ecb
   if (crypto_skcipher_setkey(skcipher, W_CRYPTOKEY, 16)) {
	pr_info("chave criptografica nao pode ser setada\n");
	skcipher_request_free(request);
	crypto_free_skcipher(skcipher);
	return -1;
   }
   printk(KERN_INFO "CRYPTO: Key setada: %s\n",W_CRYPTOKEY);

   if(nbytes >= strlen(originalText))
   	cipherlen = ((strlen(originalText)/16) + 1)*16;
   else
   	cipherlen = ((nbytes/16 + 1)*16);

   // Aloca buffer para armazenar a mensagem original
   plaintext = kmalloc(cipherlen, GFP_KERNEL);
   if (!plaintext) {
        pr_info("plaintext nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	return -1;
   }
   printk(KERN_INFO "CRYPTO: Texto original: %s\n",originalText);

   sk.tfm = skcipher;
   sk.request = request;

   // Aloca buffer para receber a mensagem original em HEX
   buffer = kmalloc(257,GFP_KERNEL);
   if (!buffer) {
        pr_info("buf nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(plaintext);
	return -1;
   }

   // Converte a mensagem original para HEX
   for(i=0,j=0;i<strlen(originalText);i++,j+=2){
	 sprintf((char*)buffer+j,"%02X",originalText[i]);
   }
   buffer[j] = '\0';
   printk(KERN_INFO "CRYPTO: Texto em hexadecimal: %s\n",buffer);

   // Aloca buffer para o resultado cifrado da mensagem
   ciphertext = kmalloc(257,GFP_KERNEL);
   if (!ciphertext) {
        pr_info("ciphertext nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(plaintext);
	kfree(buffer);
	return -1;
    }
   
   // Define a parte da palavra que vai ser cifrada
   if(nbytes >= strlen(originalText))
	ret = lenght = strlen(originalText);
   else
	ret = lenght = nbytes;

   // Copia a parte da mensagem original para o buffer
   for(i = 0; i < lenght; i++){
	plaintext[i] = originalText[i];
   } 
   plaintext[i] = '\0';

   memset(plaintext+strlen(plaintext),0,cipherlen - strlen(plaintext)); // Realiza padding

   // Inicializa scatterlist de origem e destino da cifragem
   sg_set_buf(&sk.source, plaintext, cipherlen);
   sg_set_buf(&sk.destination, ciphertext, cipherlen);   

   // Inicializa a requisição de cifragem
   skcipher_request_set_crypt(request, &sk.source, &sk.destination, cipherlen, NULL);
   init_completion(&sk.result.completion);

   // Chama função de cifragem
   if(w_skcipher_encdec(&sk, 1)){
	printk(KERN_INFO "erro ao cifrar\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(plaintext);
	kfree(buffer);
	kfree(ciphertext);
	return -1;
   }  
   printk(KERN_INFO "CRYPTO: Sucesso ao cifrar\n");

   // Converte mensagem cifrada para HEX
   for(i=0,j=0;i<cipherlen;i++,j+=2){
	sprintf((char*)buffer+j,"%02hhX",ciphertext[i]);
   }
   buffer[j] = '\0';

   printk(KERN_INFO "CRYPTO: Texto cifrado em hexadecimal: %s\n",buffer);

   f = fdget_pos(fd);
   kernel_write(f.file, buffer, strlen(buffer), &pos);// Escreve no arquivo

   // Desaloca recursos
   skcipher_request_free(request);
   crypto_free_skcipher(skcipher);
   kfree(plaintext);
   kfree(buffer);
   kfree(ciphertext);

   return ret;
}


