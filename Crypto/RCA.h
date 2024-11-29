#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <iostream>

void errors() {
	ERR_print_errors_fp(stderr);
	abort();
}

class RCA {
private: 
	EVP_PKEY* generate_evp_pkey(unsigned int bits) {
		EVP_PKEY* pkey = EVP_RSA_gen(bits);
		if (!pkey) {
			errors();
		}

		FILE* pr_key_file = fopen("private_key.pem", "wb");
		if (!pr_key_file || !PEM_write_PrivateKey(pr_key_file, pkey, NULL, NULL, 0, NULL, NULL)) {
			errors();
			fclose(pr_key_file);
		}

		FILE* pub_key_file = fopen("public_key.pem", "wb");
		if (!pub_key_file || !PEM_write_PUBKEY(pub_key_file, pkey)) {
			errors();
			fclose(pub_key_file);
		}

		return pkey;
	}


};