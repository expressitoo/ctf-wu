#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>

char aes_key[] = "TH3Gr3eNSh4rDk3y";
char aes_iv[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

uint32_t encrypt_buffer(const void *plaintext, unsigned int plaintext_len, char *key, char *iv, char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    uint32_t len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), 0LL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, &ciphertext[len], &len);
    EVP_CIPHER_CTX_free(ctx);
    return *(uint32_t *)(&ciphertext[0x28]);
}

void main(void)
{
    char ciphertext[0x100];
    uint8_t payload[0x20];
    uint32_t id;

    for (int init_byte = 0; init_byte < 0x100; init_byte++) {
        memset(payload, init_byte, sizeof(payload));
        for (int idx = 0; idx < sizeof(payload); idx++) {
            for (int byte = 0; byte < 0x100; byte++) {
                payload[idx] = byte;
                memset(ciphertext, 0, sizeof(ciphertext));
                id = encrypt_buffer((char *)&payload, 0x20, (char *)&aes_key, (char *)&aes_iv, (char *)&ciphertext);
                //if (id == 0x00000db) {
                //    for (int payload_idx = 0; payload_idx < sizeof(payload); payload_idx++) {
                //        printf("%02x", payload[payload_idx]);
                //    }
                //    puts("");
                //}
                printf("%08x\n", id);
            }
        }
    }
}