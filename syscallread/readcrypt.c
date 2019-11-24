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

#define	 R_CRYPTOKEY "0123456789ABCDEF"

struct readtcrypt_result {
    struct completion completion;
    int err;
}ra;

struct read_skcipher_def {
    struct scatterlist source;
    struct scatterlist destination;
    struct crypto_skcipher *tfm;
    struct skcipher_request *request;
    struct readtcrypt_result result;
}rb;

static unsigned int r_skcipher_encdec(struct read_skcipher_def *sk, int enc)
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

asmlinkage extern ssize_t read_crypt(int fd, void *buf, size_t nbytes){

   struct read_skcipher_def sk;
   struct crypto_skcipher *skcipher = NULL;
   struct skcipher_request *request = NULL;
   int ret = 0;
   int i,j;
   int cipherlen;

   char *ciphertext = NULL;	// Buffer para a mensagem cifrada
   char *plaintext = NULL;	// Buffer para a mensagem a ser decifrada
   char string[257];		// Buffer para receber a conversão da mensagem
   char readaux[257];		// Buffer para preparar resposta ao usuário

   char *text = NULL;           // Buffer para receber a conversão em HEX
   struct fd f;

   loff_t pos = 0;

   // Aloca skcipher em modo de cifragem cbc
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
   printk(KERN_INFO "CRYPTO: Request alocada\n");

   // Seta chave criptográfica para o skcipher em modo ecb  
   if (crypto_skcipher_setkey(skcipher, R_CRYPTOKEY, 16)) {
        pr_info("chave Criptografica nao pode ser setada\n");
	skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	return -1;
   }
   printk(KERN_INFO "CRYPTO: Key setada: %s\n",R_CRYPTOKEY);

   f = fdget_pos(fd);
   if(kernel_read(f.file, string, 256, &pos) < 0)//Lê arquivo de texto
	return -1;

   // Aloca buffer para receber a conversão da mensagem de HEX para ASCII
   text = kmalloc(129,GFP_KERNEL);
   if (!text) {
        pr_info("text nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	return -1;
   }

   // Converte mensagem cifrada para ASCII 
   for(i = 0, j = 0; j < strlen(string); ++i, j += 2){
	int val[1];
	char aux[9];
	
	aux[0] = string[j];
	aux[1] = string[j+1];
	aux[2] = '\0';

	sscanf(aux,"%2x",val);
	text[i] = val[0];
   }	
   text[i] = '\0';

   cipherlen = ((strlen(text)/16 + 1)*16); // Calcula tamanho da mensagem (multiplo de 16 bytes)

   //Aloca buffer a mensagem cifrada
   ciphertext = kmalloc(cipherlen, GFP_KERNEL);
   if (!ciphertext) {
        pr_info("ciphertext nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(text);
	return -1;
   }

   strcpy(ciphertext,text); // Copia mensagem cifrada para o buffer
   memset(ciphertext+strlen(ciphertext),0,cipherlen - strlen(ciphertext)); // Realiza padding

   sk.tfm = skcipher;
   sk.request = request;

   // Aloca buffer para o resultado decifrado da mensagem
   plaintext = kmalloc(257,GFP_KERNEL);
   if (!plaintext) {
        pr_info("plaintext nao pode ser alocado\n");
        skcipher_request_free(request);
        crypto_free_skcipher(skcipher);
	kfree(text);
	kfree(ciphertext);
	return -1;
   }
   printk(KERN_INFO "CRYPTO: Texto cifrado: %s\n",string);

   // Inicializa scatterlist de origem e destino da decifragem
   sg_set_buf(&sk.source, ciphertext, cipherlen);
   sg_set_buf(&sk.destination, plaintext,cipherlen);

   // Inicializa a requisição de decifragem
   skcipher_request_set_crypt(request, &sk.source, &sk.destination, cipherlen, NULL);
   init_completion(&sk.result.completion);

   //Chama função de cifragem/decifragem
   if(r_skcipher_encdec(&sk, 0)){

	printk(KERN_INFO "erro ao cifrar\n");
	crypto_free_skcipher(skcipher);
	skcipher_request_free(request);
	kfree(text);
	kfree(ciphertext);
	kfree(plaintext);
	return -1;
   }

   pr_info("CRYPTO: Sucesso ao decifrar\n");
   printk(KERN_INFO "CRYPTO: Texto decifrado: %s\n",plaintext);

   // Envia a parte decifrada que o usuario pediu
   if(nbytes >= strlen(plaintext)){
	strcpy((char*)buf,plaintext);
	ret = strlen(plaintext);
   }
   else{
	for(i = 0; i < nbytes; i++){
	  readaux[i] = plaintext[i];
	}
	
	readaux[i] = '\0';

	ret = nbytes;
	strcpy((char*)buf,readaux);
   }

   // Desaloca recursos
   crypto_free_skcipher(skcipher);
   skcipher_request_free(request);
   kfree(text);
   kfree(ciphertext);
   kfree(plaintext);

   return ret;
}


