#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "secp256k1.h"
#include "utils.h"
#include "RLP.h"
#include "sha3.h"

void createPrivateKey(unsigned char *privateKey) {
	int i;
	for(i=0; i < 32; i++) {
		privateKey[i] = rand() % 256;
	}
}

void printCharArray(unsigned char *privateKey, uint8_t length) {
	int i;
	for(i=0; i < length; i++) {
		printf("%02x", privateKey[i]);
	}
	printf("\n");
}

int wallet_ethereum_assemble_tx(EthereumSignTx *msg, EthereumSig *tx, uint64_t *rawTx) {
    EncodeEthereumSignTx new_msg;
    EncodeEthereumTxRequest new_tx;
    memset(&new_msg, 0, sizeof(new_msg));
    memset(&new_tx, 0, sizeof(new_tx));

    wallet_encode_element(msg->nonce.bytes, msg->nonce.size,
                          new_msg.nonce.bytes, &(new_msg.nonce.size), false);
    wallet_encode_element(msg->gas_price.bytes, msg->gas_price.size,
                          new_msg.gas_price.bytes, &(new_msg.gas_price.size), false);
    wallet_encode_element(msg->gas_limit.bytes, msg->gas_limit.size,
                          new_msg.gas_limit.bytes, &(new_msg.gas_limit.size), false);
    wallet_encode_element(msg->to.bytes, msg->to.size, new_msg.to.bytes,
                          &(new_msg.to.size), false);
    wallet_encode_element(msg->value.bytes, msg->value.size,
                          new_msg.value.bytes, &(new_msg.value.size), false);
    wallet_encode_element(msg->data_initial_chunk.bytes,
                          msg->data_initial_chunk.size, new_msg.data_initial_chunk.bytes,
                          &(new_msg.data_initial_chunk.size), false);

    wallet_encode_int(tx->signature_v, &(new_tx.signature_v));
    wallet_encode_element(tx->signature_r.bytes, tx->signature_r.size,
                          new_tx.signature_r.bytes, &(new_tx.signature_r.size), true);
    wallet_encode_element(tx->signature_s.bytes, tx->signature_s.size,
                          new_tx.signature_s.bytes, &(new_tx.signature_s.size), true);

    int length = wallet_encode_list(&new_msg, &new_tx, rawTx);
    return length;
}

void assembleTx() {
    static char rawTx[256];
    EthereumSignTx tx;
    EthereumSig signature;
    uint64_t raw_tx_bytes[24];
    const char *nonce = "00";
    const char *gas_price = "4a817c800";
    const char *gas_limit = "5208";
    const char *to = "e0defb92145fef3c3a945637705fafd3aa74a241";
    const char *value = "de0b6b3a7640000";
    const char *data = "00";
    const char *r = "09ebb6ca057a0535d6186462bc0b465b561c94a295bdb0621fc19208ab149a9c";
    const char *s = "440ffd775ce91a833ab410777204d5341a6f9fa91216a6f3ee2c051fea6a0428";
    uint32_t v = 27;

    tx.nonce.size = size_of_bytes(strlen(nonce));
    hex2byte_arr(nonce, strlen(nonce), tx.nonce.bytes, tx.nonce.size);

    tx.gas_price.size = size_of_bytes(strlen(gas_price));
    hex2byte_arr(gas_price, strlen(gas_price), tx.gas_price.bytes, tx.gas_price.size);

    tx.gas_limit.size = size_of_bytes(strlen(gas_limit));
    hex2byte_arr(gas_limit, strlen(gas_limit), tx.gas_limit.bytes, tx.gas_limit.size);

    tx.to.size = size_of_bytes(strlen(to));
    hex2byte_arr(to, strlen(to), tx.to.bytes, tx.to.size);

    tx.value.size = size_of_bytes(strlen(value));
    hex2byte_arr(value, strlen(value), tx.value.bytes, tx.value.size);

    tx.data_initial_chunk.size = size_of_bytes(strlen(data));
    hex2byte_arr(data, strlen(data), tx.data_initial_chunk.bytes,
                 tx.data_initial_chunk.size);

    signature.signature_v = 27;

    signature.signature_r.size = size_of_bytes(strlen(r));
    hex2byte_arr(r, strlen(r), signature.signature_r.bytes, signature.signature_r.size);

    signature.signature_s.size = size_of_bytes(strlen(s));
    hex2byte_arr(s, strlen(s), signature.signature_s.bytes, signature.signature_s.size);

    int length = wallet_ethereum_assemble_tx(&tx, &signature, raw_tx_bytes);
    int8_to_char((uint8_t *) raw_tx_bytes, length, rawTx);
    printf("raw transaction: %s\n", rawTx);
}


int main() {

    /* create key pair */
	unsigned char privateKey[32];
	static secp256k1_context *ctx = NULL;
	srand(time(NULL));

	createPrivateKey(privateKey);
	printf("개인키: ");
	printCharArray(privateKey, 32);
	printf("개인키 검증: %d\n", secp256k1_ec_seckey_verify(ctx, privateKey));

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	secp256k1_pubkey publicKey;

	secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey);
	printf("공개키: ");
	printCharArray(publicKey.data, 64);
	
	printf("공개키 검증: %d\n", secp256k1_ec_pubkey_negate(ctx, &publicKey));
    printf("\n");

    /* rlp */
	assembleTx();
    printf("\n");

    /* keccak */
    uint8_t buf[32];
    sha3_context c;
    const uint8_t *hash;
    unsigned i;

    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, "abc", 3, buf, sizeof(buf));
    printCharArray(buf, 32);
    if(memcmp(buf, "\x4e\x03\x65\x7a\xea\x45\xa9\x4f"
                   "\xc7\xd4\x7b\xa8\x26\xc8\xd6\x67"
                   "\xc0\xd1\xe6\xe3\x3a\x64\xa0\x36"
                   "\xec\x44\xf5\x8f\xa1\x2d\x6c\x45", 256 / 8) != 0) {
        printf("SHA3-256 doesn't match known answer (single buffer)\n");
    }else {
        printf("SHA3-256 matches known answer (single buffer)\n");
    }

    
	return 0;
}

