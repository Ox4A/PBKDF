#pragma warning(disable:4996)
#include <iostream>
#include<cstring>
#include<cstdio>
#include<iomanip>
#include<string>
#include <cstring>
#include <openssl/sha.h>
#include<openssl/evp.h>
#include<openssl/hmac.h>
#include<openssl/aes.h>
#include<openssl/rand.h>
#define IV_LEN 16
#define KEY_LEN 32
#define HMAC_BLOCK_SIZE 64 // HMAC 块大小
unsigned char salt[16];
using namespace std;

void My_SHA256(const unsigned char* input,unsigned char* output) {
    /*
    input:原消息
    output：存储消息摘要
    */
    SHA256_CTX sha256_handler;

    SHA256_Init(&sha256_handler);
    SHA256_Update(&sha256_handler, input, strlen((char*)input));
    SHA256_Final(output, &sha256_handler);
}

void My_HMAC(const unsigned char* key, int key_len, const unsigned char* data, int data_len, unsigned char* result) {
    // 如果密钥长度大于 HMAC_BLOCK_SIZE，则将其进行 SHA-256 哈希
    unsigned char key_hash[SHA256_DIGEST_LENGTH];
    if (key_len > HMAC_BLOCK_SIZE) {
        My_SHA256(key, key_hash);
        strcpy((char*)key, (char*)key_hash);
        key_len = SHA256_DIGEST_LENGTH;
    }

    // 创建内部填充和外部填充
    unsigned char inner_key_pad[HMAC_BLOCK_SIZE];
    unsigned char outer_key_pad[HMAC_BLOCK_SIZE];

    // 填充内部密钥和外部密钥
    memset(inner_key_pad, 0x36, HMAC_BLOCK_SIZE);
    memset(outer_key_pad, 0x5c, HMAC_BLOCK_SIZE);

    for (int i = 0; i < key_len; ++i) {
        inner_key_pad[i] ^= key[i];
        outer_key_pad[i] ^= key[i];
    }

    // 计算内部哈希
    unsigned char* inner_hash = new unsigned char[HMAC_BLOCK_SIZE + data_len];
    memcpy(inner_hash, inner_key_pad, HMAC_BLOCK_SIZE);
    memcpy(inner_hash + HMAC_BLOCK_SIZE, data, data_len);
    My_SHA256(inner_hash, result);

    // 计算最终哈希
    unsigned char* final_hash = new unsigned char[HMAC_BLOCK_SIZE + SHA256_DIGEST_LENGTH];
    memcpy(final_hash, outer_key_pad, HMAC_BLOCK_SIZE);
    memcpy(final_hash + HMAC_BLOCK_SIZE, result, SHA256_DIGEST_LENGTH);
    My_SHA256(final_hash, result);
    delete[] inner_hash;
    delete[] final_hash;
}

void PBKDF(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned char* key, size_t key_len, int iterations) {
    const int hash_len = SHA256_DIGEST_LENGTH;
    if ((long long)key_len > (long long)hash_len * 2147483647) {
        cout << "the size of key too long" << endl;
        return;
    }
    unsigned char result[hash_len];
    unsigned char temp[hash_len];

    for (int i = 1; i <= iterations; ++i) {
        // 使用HMAC-SHA256计算PRF
        My_HMAC(password, password_len, salt, salt_len, result);

        // 将PRF的结果与temp异或
        memcpy(temp, result, hash_len);
        for (int j = 1; j < i; ++j) {
            My_HMAC(password, password_len, temp, hash_len, temp);
            for (int k = 0; k < hash_len; ++k) {
                result[k] ^= temp[k];
            }
        }

        // 将结果复制到key中
        if (i * hash_len <= key_len) {
            memcpy(key + (i - 1) * hash_len, result, hash_len);
        }
        else {
            memcpy(key + (i - 1) * hash_len, result, key_len % hash_len);
            break;
        }
    }
}

bool aes_cbc_encrypt(unsigned char* in, unsigned char* out,const unsigned char* password,size_t password_len)
{
    unsigned char iv[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) { iv[i] = 0; }

    unsigned char master_key[17];
    RAND_bytes(salt, 16);
    PBKDF(password, password_len, salt, 16, master_key, 16, 1000);
    cout << endl;

    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char*)master_key, 128, &aes) < 0)
    {
        return false;
    }
    int len = strlen((const char*)in);
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
    return true;
}

// CBC模式解密
bool aes_cbc_decrypt(unsigned char* in,unsigned char* out,const unsigned char* password,size_t password_len)
{
    unsigned char master_key[17];
    PBKDF(password, password_len, salt, 16, master_key, 16, 1000);

    // 加密的初始化向量
    unsigned char iv[AES_BLOCK_SIZE];

    // iv一般设置为全0
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) { iv[i] = 0; }

    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char*)master_key, 128, &aes) < 0)
    {
        return false;
    }
    int len = strlen((const char*)in);
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
    return true;
}