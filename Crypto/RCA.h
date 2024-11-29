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

bool is_exist(const char* filename) {
	FILE* file = fopen(filename, "rb");
	if (file) {
		fclose(file);
		return true;
	}
	return false;
}

class RCA {
private: 

	EVP_PKEY* pkey;
	X509* cert;
	const char* pr_key_filename = "private_key.pem";
	const char* pub_key_filename = "public_key.pem";

	RCA() {
		if (!is_exist(pr_key_filename) || !is_exist(pub_key_filename)) {
			generate_evp_pkey(2048);
		}
		else {
			FILE* pr_key_file = fopen(pr_key_filename, "rb");
			pkey = PEM_read_PrivateKey(pr_key_file, NULL, NULL, NULL);
		}
	}

	void  generate_evp_pkey(unsigned int bits) {
		pkey = EVP_RSA_gen(bits);
		if (!pkey) {
			errors();
		}
	
		save_evp_pkey(pkey);
	}

	void save_evp_pkey(EVP_PKEY* _pkey) {
		FILE* pr_key_file = fopen(pr_key_filename, "wb");
		if (!pr_key_file || !PEM_write_PrivateKey(pr_key_file, _pkey, NULL, NULL, 0, NULL, NULL)) {
			errors();
		}

		FILE* pub_key_file = fopen(pub_key_filename, "wb");
		if (!pub_key_file || !PEM_write_PUBKEY(pub_key_file, _pkey)) {
			errors();
		}

		if (pr_key_file) fclose(pr_key_file);
		if (pub_key_file) fclose(pub_key_file);
	}

	void generate_self_signed_cert() {
		cert = X509_new();

		ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

		X509_gmtime_adj(X509_get_notBefore(cert), 0);
		X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 365);

		X509_set_pubkey(cert, pkey);

		X509_NAME* name = X509_get_subject_name(cert);

		X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*) "BY", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*) "BelHard", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*) "Root", -1, -1, 0);

		X509_set_issuer_name(cert, name);
	}

public:
	~RCA() {
		delete pkey;
		delete pr_key_filename;
		delete pub_key_filename;
	}
};