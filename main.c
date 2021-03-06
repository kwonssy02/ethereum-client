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
    srand(time(NULL));

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
/*
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
    wallet_encode_int(tx->signature_v, &(new_tx.signature_v));

    wallet_encode_element(tx->signature_r.bytes, tx->signature_r.size,
                          new_tx.signature_r.bytes, &(new_tx.signature_r.size), true);
    wallet_encode_element(tx->signature_s.bytes, tx->signature_s.size,
                          new_tx.signature_s.bytes, &(new_tx.signature_s.size), true);

    int length = wallet_encode_list(&new_msg, &new_tx, rawTx);
    //printf("%x",data_initial_chunk.bytes);
    return length;
}
*/

void assembleTx(struct RawTxStruct rts, char * rlpre) {
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
    length = wallet_ethereum_assemble_tx(&tx, &signature, raw_tx_bytes);
    /*
    if (withRSV) {    
	    length = wallet_ethereum_assemble_tx(&tx, &signature, raw_tx_bytes);
    } else { 
	    length = wallet_ethereum_assemble_tx_s(&tx, &signature, raw_tx_bytes);
    }
    */
    // printf("%i",raw_tx_bytes);
    // int length = 110;
    int8_to_char((uint8_t *) raw_tx_bytes, length, rawTx);
    sprintf(rlpre, "%s", rawTx);
}

void keyPairTest() {

    static secp256k1_context *ctx = NULL;
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /* create key pair */
    // privateKey: f4259e890d999a567d9709181401364e93ce2b1deceed603700b5bdb9c0044a3
    // publicKey: da48faca2e0632ec4df6ad941521aab6dcbca70df3b88b517eef603275602f4f
    // address: 0xEEC267C64d2d4b036075E426DC34429cBb9501a4
    
	unsigned char privateKey[32];
	// createPrivateKey(privateKey);
    unsigned char *privateKeyStr = "f4259e890d999a567d9709181401364e93ce2b1deceed603700b5bdb9c0044a3"; // privateKey import from string
    hex2byte_arr(privateKeyStr, 64, privateKey, 32);

	printf("개인키: ");
	printCharArray(privateKey, 32);
	// printf("개인키 검증: %d\n", secp256k1_ec_seckey_verify(ctx, privateKey));

	secp256k1_pubkey publicKey;
	secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey); // get publicKey from privateKey
    unsigned char publicKeyBuf[65]; // before removing front 04
    size_t clen = 65;
    unsigned char publicKeyStr[64]; // after removing front 04
    secp256k1_ec_pubkey_serialize(ctx, &publicKeyBuf, &clen, &publicKey, SECP256K1_EC_UNCOMPRESSED);
    strncpy(publicKeyStr, publicKeyBuf+1, 64); // remove front 04
    
	printf("공개키: ");
	printCharArray(publicKeyStr, 64);
	// printf("공개키 검증: %d\n", secp256k1_ec_pubkey_negate(ctx, &publicKey));

    // 주소값 생성
    uint8_t buf[32];

    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, &publicKeyStr, 64, buf, sizeof(buf));
    unsigned char address[20];
    strncpy(address, buf+12, 20); // get last 20 bytes from hash
    printf("주소값: ");
    printCharArray(address, 20);

}

void rlpTest() {
    unsigned char privateKey[32];
    unsigned char *privateKeyStr = "f4259e890d999a567d9709181401364e93ce2b1deceed603700b5bdb9c0044a3"; // privateKey import from string
    hex2byte_arr(privateKeyStr, 64, privateKey, 32);

    /* rlp */

    struct RawTxStruct rts;
	rts.nonce = "01";
	rts.gas_price = "9184e72a000";
	rts.gas_limit = "2710";
	rts.to = "eec267c64d2d4b036075e426dc34429cbb9501a4";
	rts.value = "17";
	rts.data = "7f";
	rts.r = "0";
	rts.s = "0";
	rts.v = 15; // chainID
    char rawTxNotSigned[200];


	assembleTx(rts, rawTxNotSigned);
    printf("\n\n");
    printf("RLP Before Signing: %s \n", rawTxNotSigned); // e5018609184e72a00082271094eec267c64d2d4b036075e426dc34429cbb9501a4177f0f8080
    printf("strlen(RLP Before Signing): %ld \n\n", strlen(rawTxNotSigned));

    // unsigned char rlp[38];
    unsigned char rlp[100];
    hex2byte_arr(rawTxNotSigned, strlen(rawTxNotSigned), rlp, strlen(rawTxNotSigned)/2); // string to byte array
    // printf("RLP: ");
    // printCharArray(rlp, strlen(rawTxNotSigned)/2);

    // message hash
    uint8_t msgHashBuf[32];
    sha3_HashBuffer(256, SHA3_FLAGS_KECCAK, &rlp, strlen(rawTxNotSigned)/2, msgHashBuf, sizeof(msgHashBuf));
    printf("MsgHash: "); 
    printCharArray(msgHashBuf, 32); // f2bace35c7d14f60fe3a1c973356fa0c7acddde64384a68a9eba8e475a1e596a

    // r, s 계산
    unsigned char rs[64];
    static secp256k1_context *ctx = NULL;
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_ecdsa_signature signature;
    secp256k1_ecdsa_sign(ctx, &signature, msgHashBuf, privateKey, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_compact(ctx, rs, &signature);
    // printf("R/S: ");
    // printCharArray(rs, 64); // ea66d7c53858d54a1166a25beab36088c86c2ed9e59a9ab892002ab41d08e6b548a51bf6f5a82a6349ecccaf5dd456bcebf0a43d2b894c3939b14641b99f2070

    unsigned char rHex[65];
    unsigned char sHex[65];

    int index = 0;
    for(int i=0; i<32; i++) {
        index += sprintf(rHex+index, "%02x", rs[i]);
    };
    printf("rHex: %s\n", rHex); // ea66d7c53858d54a1166a25beab36088c86c2ed9e59a9ab892002ab41d08e6b5

    index = 0;
    for(int i=32; i<64; i++) {
        index += sprintf(sHex+index, "%02x", rs[i]);
    };
    printf("sHex: %s\n", sHex); // 48a51bf6f5a82a6349ecccaf5dd456bcebf0a43d2b894c3939b14641b99f2070
    
    // r, s 세팅 후 RLP 계산
    rts.r = rHex; 
    rts.s = sHex; 
    rts.v = 28 + rts.v * 2 + 8;
    char rawTxSigned[3000];
	assembleTx(rts, rawTxSigned);
    printf("RLP After Signing: %s \n", rawTxSigned);
    // printf("strlen(RLP After Signing): %ld \n", strlen(rawTxSigned));

}

int main() {
    
    keyPairTest();
    rlpTest();

	return 0;
}

