#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <ctype.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

//INPUT COMMAND: openssl enc -aes-192-cbc -pbkdf2 -e -in <infile.txt> -out ciphertext.enc

int plain_isascii(unsigned char *plaintext, int plaintext_len){
	int i;
	for(i=0; i < plaintext_len; i++){
		int ch = plaintext[i];
		if (isascii(ch)) continue;
		else return 0;
	}
	return 1;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, const char *password, unsigned char* salt){
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len, i;

    //Simulation of the -pbkdf2 command with default parameters: iter = 10000, dgst = sha256
    unsigned char tmpkeyiv[EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH];
    int iklen = EVP_CIPHER_key_length(EVP_aes_192_cbc());
    int ivlen = EVP_CIPHER_iv_length(EVP_aes_192_cbc());
    unsigned char key[iklen], iv[ivlen];

    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, strlen((char*) salt), 10000, EVP_sha256(), iklen+ivlen, tmpkeyiv);

		memcpy(key, tmpkeyiv, iklen);
    memcpy(iv, tmpkeyiv+iklen, ivlen);

    //printf("Key: "); for(i=0; i < 24; ++i){ printf("%02x", key[i]); } printf("\n");
    //printf("IV: "); for(i=0; i < 16; ++i){ printf("%02x", iv[i]); } printf("\n\n");

    //Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    //Initialise the decryption operation. IMPORTANT - ensure you use a key and IV size appropriate for your cipher
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv)) return -1;

    //Provide the message to be decrypted, and obtain the plaintext output. EVP_DecryptUpdate can be called multiple times if necessary.
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;

    //Finalise the decryption. Further plaintext bytes may be written at this stage.
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;
    plaintext_len += len;

    //Clean up
    EVP_CIPHER_CTX_free(ctx);

    return 1;
}


int main (int argc, char **argv){

	unsigned char* dict;
	unsigned char* cipher;
	unsigned long dict_size, cipher_size;
	clock_t start, end;													// clock for timing
	int i = 0;

	if(argc < 3){
		printf("Usage ./offline_dictionary_attack <dictionary> <ciphertext>\n");
		exit(1);
	}

	printf("*** READING CIPHERTEXT ***\n");
	char* ciphertext = argv[2];
	int cipher_fd = open(ciphertext, O_RDONLY, (mode_t)0666);
	int cipher_fdr = cipher_fd;
	if(cipher_fd == -1) fprintf(stderr, "Error in open file\n");
	cipher_size = lseek(cipher_fd, 0, SEEK_END);
	cipher = malloc(sizeof(char)*cipher_size);
	cipher = mmap(0, cipher_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, cipher_fdr, 0);

	unsigned long plaintext_size = cipher_size;
	unsigned char* plaintext = malloc((sizeof(char)*plaintext_size));

	printf("*** EXTRACTING SALT ***\n");
	unsigned char salt[8];
	for(i = 8; i < 16; i++){
		salt[i-8] = cipher[i];
	}
	cipher = cipher + 16;																													//We don't want decrypt the salt
	cipher_size -= 16;

	printf("SALT: "); for(i=0; i < 8; ++i){ printf("%02x", salt[i]); } printf("\n");
	printf("CIPHER SIZE: %ld\n", cipher_size);

	printf("*** DICTIONARY ATTACK ***\n");
	char* dictionary = argv[1];
	char* line = NULL;
	ssize_t read;
	size_t len = 0;
	FILE* dict_fp = fopen(dictionary, "r");
	if(dict_fp == NULL) fprintf(stderr, "Error in open file\n");

	start = clock();
	while(1){
		read = getline(&line, &len, dict_fp);
		unsigned char* password = malloc(sizeof(char)*(strlen(line)-1));
		memcpy(password, line, (strlen(line)-1));
		if(read == -1)
			break;
		if(decrypt(cipher, cipher_size, plaintext, (const char*)password, salt) == 1 && plain_isascii(plaintext, plaintext_size)){
			printf("*** YOU WIN ***\n");
			printf("PASSWORD: %s\n", password);
			printf("%s\n", plaintext);
			break;
		}
	}
	end = clock();
	fclose(dict_fp);

	double dec_time = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("  Time ===> %lf\n", dec_time);

	free(plaintext);
	free(cipher);

	return 0;
}
