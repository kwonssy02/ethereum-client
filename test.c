// #include "uECC.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "secp256k1/include/secp256k1.h"

void createPrivateKey(unsigned char *privateKey) {
	int i;
	for(i=0; i < 32; i++) {
		privateKey[i] = rand() % 256;
		// printf("%d ", privateKey[i]);
	}
}

void printCharArray(unsigned char *privateKey) {
	int i;
	for(i=0; i < 32; i++) {
		printf("%02x", privateKey[i]);
	}
	printf("\n");
}

int main()
{
	unsigned char privateKey[32];
	srand(time(NULL));

	createPrivateKey(privateKey);
	printf("개인키: ");
	printCharArray(privateKey);

	printf("개인키: E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262\n");

	static secp256k1_context *ctx = NULL;
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	secp256k1_pubkey publicKey;

	//secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey);
	printf("공개키: ");
	printCharArray(publicKey.data);
	return 0;
}

