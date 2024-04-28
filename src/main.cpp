#include<iostream>
#include<cstring>
#include<openssl/bio.h>
#include<openssl/evp.h>
#include<openssl/buffer.h>
using namespace std;
#include"PasswordEncrypt.h"
unsigned char cipher[1000];
unsigned char plain_recover[1000];
unsigned char plain[1000];
char* Base64Encode(const unsigned char* input, int length) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    return bufferPtr->data;
}
int main() {
	string password;
	cout << "请输入口令：";
	cin >> password;
	cout << "请输入明文：";
	cin >> plain;
	bool check = aes_cbc_encrypt(plain, cipher, (unsigned char*)password.c_str(), password.size());
	if (check) {
        cout << "密文（Base64编码）：" << Base64Encode(cipher,strlen((char*)cipher))<<endl;
		aes_cbc_decrypt(cipher, plain_recover, (unsigned char*)password.c_str(), password.size());
		cout << "验证：恢复明文="<<plain_recover;
	}
}
