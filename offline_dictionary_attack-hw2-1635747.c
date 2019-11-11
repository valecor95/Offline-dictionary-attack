#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <time.h>
/*
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;
*/
    /* Create and initialise the context */
    //if(!(ctx = EVP_CIPHER_CTX_new()))
    //    handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     */
		//if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
			//	handleErrors();
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    //if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    //    handleErrors();
    //plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    //if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    //    handleErrors();
    //plaintext_len += len;

    /* Clean up */
    //EVP_CIPHER_CTX_free(ctx);
//}


int main (int argc, char **argv)
{

	/* Message to be encrypted */
	/*****************************************************************************************************************************/
	unsigned char* dict;													// Structure for input file
	unsigned long dict_size;
  unsigned char* cipher;													// Structure for input file
	unsigned long cipher_size;

  printf("*** READING DICTIONARY ***\n");
  char* dictionary = argv[1];
  char line[200];
  char* res;
	FILE* dict_fd = fopen(dictionary, "r");
	if(dict_fd == NULL) fprintf(stderr, "Error in open file\n");
	//dict_size = lseek(dict_fd, 0, SEEK_END);
	//dict = malloc(sizeof(char)*dict_size);
	//dict = (char*) mmap(0, dict_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, dict_fdr, 0);
  while(1) {
    res = fgets(line, 200, dict_fd);
    if(res == NULL)
      break;
    printf("%s", line);
  }
  fclose(dict_fd);

  printf("*** READING CIPHERTEXT ***\n");
  char* ciphertext = argv[2];
	int cipher_fd = open(ciphertext, O_RDONLY, (mode_t)0666);
	int cipher_fdr = cipher_fd;
	if(cipher_fd == -1) fprintf(stderr, "Error in open file\n");
	cipher_size = lseek(cipher_fd, 0, SEEK_END);
	cipher = malloc(sizeof(char)*cipher_size);
	cipher = mmap(0, cipher_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, cipher_fdr, 0);
	close(cipher_fd);

	printf("*** END READING FILES ***\n\n");
	/*****************************************************************************************************************************/
	unsigned char* key_192 = malloc(sizeof(char)*24);
	unsigned char* iv_192 = malloc(sizeof(char)*24);
	unsigned char* aux_iv_192 = malloc(sizeof(char)*24);
	clock_t start, end;																				                    // clock for timing
	int i = 0;


	printf("********************************************* Cipher Algorithm: AES *********************************************\n\n");
	int plaintext_size = cipher_size;
	unsigned char* plaintext = malloc((sizeof(char)*plaintext_size));

	/*printf("	DECRYPTING");
	memcpy(aux_iv_192, iv_192, sizeof(iv_192));
	start = clock();
	decrypt(cipher, plaintext_size, key_128, aux_iv_128, plaintext);
	end = clock();

  printf("%s", plaintext);*/
  return 0;
}
