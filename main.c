#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "secp256k1.h"
#include "RLP/RLP.c"
#include "RLP/utils.c"
#include "sha3.h"

struct RawTxStruct {
    const char *nonce;
    const char *gas_price;
    const char *gas_limit;
    const char *to;
    const char *value;
    const char *data;
    const char *r;
    const char *s;
    uint32_t v;
};

void createPrivateKey(unsigned char *privateKey) {
	int i;
	for(i=0; i < 32; i++) {
		privateKey[i] = rand() % 256;
	}
}

void printCharArray(unsigned char *array, uint8_t length) {
	int i;
	for(i=0; i < length; i++) {
		printf("%02x", array[i]);
	}
	printf("\n");
}

char bytesToSecp256(char* key, char* msg, unsigned char *rs){
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature signature;
    
    unsigned char rands[64];
    unsigned int i;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    
    secp256k1_ecdsa_sign(ctx, &signature, msg, key, NULL, NULL);
    
    secp256k1_ecdsa_signature_serialize_compact(ctx, rands, &signature);
    
    for (i=0; i<64; i++){
	    unsigned char *tmp;
        // unsigned char tmp[2];
        sprintf(tmp, "%02x", rands[i]);
	    strcat(rs, tmp);
	}
    
    secp256k1_context_destroy(ctx);
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
    //printf("%x",data_initial_chunk.bytes);
    return length;
}

int wallet_ethereum_assemble_tx_s(EthereumSignTx *msg, EthereumSig *tx, uint64_t *rawTx) {
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
/*
    wallet_encode_int(tx->signature_v, &(new_tx.signature_v));
    wallet_encode_element(tx->signature_r.bytes, tx->signature_r.size,
                          new_tx.signature_r.bytes, &(new_tx.signature_r.size), true);
    wallet_encode_element(tx->signature_s.bytes, tx->signature_s.size,
                          new_tx.signature_s.bytes, &(new_tx.signature_s.size), true);
*/
    int length = wallet_encode_list_s(&new_msg, &new_tx, rawTx);
    //printf("%x",data_initial_chunk.bytes);
    return length;
}

void assembleTx(struct RawTxStruct rts, bool withRSV, char * rlpre) {
    static char rawTx[256];
    EthereumSignTx tx;
    EthereumSig signature;
    uint64_t raw_tx_bytes[24];

    const char *nonce = rts.nonce;
    const char *gas_price = rts.gas_price;
    const char *gas_limit = rts.gas_limit;
    const char *to = rts.to;
    const char *value = rts.value;
    const char *data = rts.data;
    const char *r = rts.r;
    const char *s = rts.s;
    uint32_t v = rts.v;

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
    signature.signature_v = v;
    signature.signature_r.size = size_of_bytes(strlen(r));
    hex2byte_arr(r, strlen(r), signature.signature_r.bytes, signature.signature_r.size);
    signature.signature_s.size = size_of_bytes(strlen(s));
    hex2byte_arr(s, strlen(s), signature.signature_s.bytes, signature.signature_s.size);
    int length;

    if (withRSV) {    
	    length = wallet_ethereum_assemble_tx(&tx, &signature, raw_tx_bytes);
    } else { 
	    length = wallet_ethereum_assemble_tx_s(&tx, &signature, raw_tx_bytes);
    }
    //printf("%i",raw_tx_bytes);
    //int length = 110;
    int8_to_char((uint8_t *) raw_tx_bytes, length, rawTx);
    sprintf(rlpre, "%s", rawTx);
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

    struct RawTxStruct rts;
	rts.nonce = "01";
	rts.gas_price = "9184e72a000";
	rts.gas_limit = "2710";
	rts.to = "0000000000000000000000000000000000000009";
	rts.value = "7";
	rts.data = "7f";
	rts.r = "0";
	rts.s = "0";
	rts.v = 15; // chainID
    char rawTxNotSigned[200];

	assembleTx(rts, true, rawTxNotSigned);
    printf("RLP Before Signing: %s \n", rawTxNotSigned);
    printf("strlen(RLP Before Signing): %d \n\n", strlen(rawTxNotSigned));
    // message hash
    uint8_t msgHashBuf[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, rawTxNotSigned, strlen(rawTxNotSigned), msgHashBuf, sizeof(msgHashBuf));
    printf("Message Hash: ");
    printCharArray(msgHashBuf, 32);

    // r, s 계산
    unsigned char rs[128];
    bytesToSecp256(privateKey, msgHashBuf, rs);
    printf("R/S: %s\n", rs);

    char r[65];
	strncpy(r, rs, 64);
	r[64] = 0;
    char s[65];
    strncpy(s, rs+64, 64);
    s[64] = 0;

    // r, s 세팅 후 RLP 계산
    rts.r = r;
    rts.s = s;
    char rawTxSigned[3000];
	assembleTx(rts, true, rawTxSigned);
    printf("RLP After Signing: %s \n", rawTxSigned);
    printf("strlen(RLP After Signing): %d \n", strlen(rawTxSigned));


    /* keccak */
    /*
    uint8_t buf[32];

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
    */

    
	return 0;
}

