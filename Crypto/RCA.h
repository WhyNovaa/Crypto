#ifndef RCA_H
#define RCA_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <iostream>

inline void _handle_errors() {
	ERR_print_errors_fp(stderr);
	abort();
}

inline bool _is_file_exist(const char* filename) {
	FILE* file = nullptr;
	if (fopen_s(&file, filename, "rb") == 0) {
		fclose(file);
		return true;
	}
	return false;
}

inline void print_certificate_info(X509* cert) {
	BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	if (!bio) {
		std::cerr << "Error creating BIO.\n";
		return;
	}

	if (X509_print(bio, cert) != 1) {
		std::cerr << "Error printing certificate information.\n";
		BIO_free(bio);
		return;
	}
	BIO_free(bio);
}

class RCA {
private: 
	EVP_PKEY* pkey;
	X509* cert;
	const char* pr_key_filename = "private_key.pem";
	const char* pub_key_filename = "public_key.pem";
	const char* cert_filename = "certificate.pem";

	long counter = 1;

	void save_evp_pkey(EVP_PKEY* _pkey) {
		FILE* pr_key_file = nullptr;
		if (fopen_s(&pr_key_file, pr_key_filename, "wb") != 0 || !PEM_write_PrivateKey(pr_key_file, _pkey, NULL, NULL, 0, NULL, NULL)) {
			std::cerr << "RCA: save_evp_pkey error\n";
			_handle_errors();
		}

		FILE* pub_key_file = nullptr;
		if (fopen_s(&pub_key_file, pub_key_filename, "wb") != 0 || !PEM_write_PUBKEY(pub_key_file, _pkey)) {
			std::cerr << "RCA: save_evp_pkey error\n";
			_handle_errors();
		}
		std::cout << "RCA: evp_pkey saved\n";
		if (pr_key_file) fclose(pr_key_file);
		if (pub_key_file) fclose(pub_key_file);
	}

	void save_cert(X509* x509) {
		FILE* file = nullptr;
		if (x509 == NULL) {
			std::cout << "RCA: certificate is null";
			return;
		}
		if (fopen_s(&file, cert_filename, "wb") != 0 || !PEM_write_X509(file, x509)) {
			std::cerr << "RCA: save_cert error\n";
			_handle_errors();
		}
		std::cout << "RCA: certificate saved\n";
		if (file) fclose(file);
	}

	void generate_evp_pkey(unsigned int bits) {
		pkey = EVP_RSA_gen(bits);
		if (!pkey) {
			std::cerr << "RCA: ERV_RSA_gen error\n";
			_handle_errors();
		}
		std::cout << "RCA: evp_pkey was made\n";
		save_evp_pkey(pkey);
	}

	void generate_self_signed_cert() {
		cert = X509_new();

		ASN1_INTEGER_set(X509_get_serialNumber(cert), 1L);

		X509_gmtime_adj(X509_get_notBefore(cert), 0);
		X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 365);

		X509_set_pubkey(cert, pkey);

		X509_NAME* name = X509_get_subject_name(cert);

		X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"BY", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"BelHard", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Root", -1, -1, 0);

		X509_set_subject_name(cert, name);
		X509_set_issuer_name(cert, name);
		X509_sign(cert, pkey, EVP_sha256());
		std::cout << "RCA: cert was made\n";
		save_cert(cert);
	}

public:

	RCA() {
		if (!_is_file_exist(pr_key_filename) || !_is_file_exist(pub_key_filename) || !_is_file_exist(cert_filename)) {
			generate_evp_pkey(2048);
			generate_self_signed_cert();
		}
		else {
			FILE* pr_key_file = nullptr;
			fopen_s(&pr_key_file, pr_key_filename, "rb");
			pkey = PEM_read_PrivateKey(pr_key_file, NULL, NULL, NULL);

			FILE* cert_file = nullptr;
			fopen_s(&cert_file, cert_filename, "rb");
			cert = PEM_read_X509(cert_file, NULL, NULL, NULL);

			if(cert_file) fclose(cert_file);
			if(pr_key_file) fclose(pr_key_file);
		}
		print_certificate_info(cert);
	}

	X509* sign_cert_req(X509_REQ* cert_req) {
		if (cert_req == nullptr) {
			std::cerr << "RCA: x509_req is null\n";
			return nullptr;
		}

		X509* signed_cert = X509_new();
		if (!signed_cert) {
			std::cerr << "RCA: sign_cert_req error(X509 wasn't created)\n";
			return nullptr;
		}
		
		ASN1_INTEGER_set(X509_get_serialNumber(signed_cert), counter++);

		X509_gmtime_adj(X509_get_notBefore(signed_cert), 0);
		X509_gmtime_adj(X509_get_notAfter(signed_cert), 60 * 60 * 24 * 365);

		EVP_PKEY* req_pkey = X509_REQ_get_pubkey(cert_req);
		if (req_pkey == nullptr) {
			std::cerr << "RCA: Error: Unable to get public key from certificate request\n" << std::endl;
			X509_free(signed_cert);
			return nullptr;
		}
		X509_set_pubkey(signed_cert, req_pkey);
		EVP_PKEY_free(req_pkey);


		X509_NAME* name = X509_REQ_get_subject_name(cert_req);

		X509_set_subject_name(signed_cert, name);
		X509_set_issuer_name(signed_cert, X509_get_subject_name(cert));

		if (!X509_sign(signed_cert, pkey, EVP_sha256())) {
			std::cerr << "RCA: Error: Failed to sign the certificate\n" << std::endl;
			X509_free(signed_cert);
			return nullptr;
		}

		std::cout << "RCA: cert signed successfully\n";
		X509_NAME_free(name);

		print_certificate_info(signed_cert);
		return signed_cert;
	}

	X509* get_RCA_cert() {
		return cert;
	}

	EVP_PKEY* get_EVP_PKEY() {
		return pkey;
	}
	~RCA() {
		EVP_PKEY_free(pkey);
		X509_free(cert);
	}
};


#endif