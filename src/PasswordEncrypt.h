#pragma once
#include<string>
void PBKDF(const unsigned char* password, size_t password_len, const unsigned char* salt, size_t salt_len, unsigned char* key, size_t key_len, int iterations);
bool aes_cbc_encrypt(unsigned char* in, unsigned char* out, const unsigned char* password, size_t password_len);
bool aes_cbc_decrypt(unsigned char* in, unsigned char* out, const unsigned char* password, size_t password_len);