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

	// 60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2
	unsigned char privateKey[32] = {
		96, 207, 52, 125, 188, 89, 211, 28,
		19, 88, 200, 229, 207, 94, 69, 184,
		34, 171, 133, 183, 156, 179, 42, 159,
		61, 152, 24, 71, 121, 169, 239, 194
	};
	static secp256k1_context *ctx = NULL;
	srand(time(NULL));

	// createPrivateKey(privateKey);
	printf("개인키: ");
	printCharArray(privateKey);
	printf("개인키 검증: %d\n" ,secp256k1_ec_privkey_negate(ctx, privateKey));

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	secp256k1_pubkey publicKey;

	secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey);
	printf("공개키: ");
	// printCharArray(publicKey.data);
	int j;
	for(j=0; j < 64; j++) {
		printf("%02x", publicKey.data[j]);
	}
	printf("\n");
	printf("공개키 검증: %d\n", secp256k1_ec_pubkey_negate(ctx, &publicKey));
	return 0;
}

