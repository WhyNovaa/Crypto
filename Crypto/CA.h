#pragma once
#ifndef CA_H
#define CA_H
#include "C:\Users\novik\source\repos\Crypto\Crypto/RCA.h"

class CA {
private: 
	RCA* rca;
	EVP_PKEY* pkey;
	X509* cert;
	const char* pr_key_filename = "CA_private_key.pem";
	const char* pub_key_filename = "CA_public_key.pem";
	const char* cert_filename = "CA_certificate.pem";
	long counter = 1;

	void save_evp_pkey(EVP_PKEY* _pkey) {
		FILE* pr_key_file = nullptr;
		if (fopen_s(&pr_key_file, pr_key_filename, "wb") != 0 || !PEM_write_PrivateKey(pr_key_file, _pkey, NULL, NULL, 0, NULL, NULL)) {
			std::cerr << "CA: save_evp_pkey error\n";
			_handle_errors();
		}

		FILE* pub_key_file = nullptr;
		if (fopen_s(&pub_key_file, pub_key_filename, "wb") != 0 || !PEM_write_PUBKEY(pub_key_file, _pkey)) {
			std::cerr << "CA: save_evp_pkey error\n";
			_handle_errors();
		}
		std::cout << "CA: evp_pkey saved\n";
		if (pr_key_file) fclose(pr_key_file);
		if (pub_key_file) fclose(pub_key_file);
	}

	void save_cert(X509* x509) {
		FILE* file = nullptr;
		if (x509 == NULL) {
			std::cout << "CA: certificate is null";
			return;
		}
		if (fopen_s(&file, cert_filename, "wb") != 0 || !PEM_write_X509(file, x509)) {
			std::cerr << "CA: save_cert error\n";
			_handle_errors();
		}
		std::cout << "CA: certificate saved\n";
		if (file) fclose(file);
	}

	void generate_rca_signed_cert() {
		X509_REQ* cert_req = X509_REQ_new();

		if (!cert_req) {
			std::cerr << "CA: Failed to create certificate request (CSR).\n";
			_handle_errors();
		}

		if (!X509_REQ_set_pubkey(cert_req, pkey)) {
			std::cerr << "CA: Failed to set public key in CSR.\n";
			X509_REQ_free(cert_req);
			_handle_errors();
		}


		X509_NAME* name = X509_NAME_new();
		if (!name) {
			std::cerr << "CA: Failed to create X509_NAME for CSR.\n";
			X509_REQ_free(cert_req);
			_handle_errors();
		}

		X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"BY", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"BelHard", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"CA", -1, -1, 0);


		if (!X509_REQ_set_subject_name(cert_req, name)) {
			std::cerr << "CA: Failed to create X509_NAME for CSR.\n";
			X509_NAME_free(name);
			X509_REQ_free(cert_req);
			_handle_errors();
		}
		X509_NAME_free(name);



		//if (!X509_REQ_sign(cert_req, pkey, EVP_sha256())) {
		//	std::cerr << "CA: Failed to sign CSR.\n";
		//	X509_REQ_free(cert_req);
		//	_handle_errors();
		//}
		cert = rca->sign_cert_req(cert_req);

		if (!cert) {
			std::cerr << " CA: RCA failed to sign req\n";
			X509_REQ_free(cert_req);
			_handle_errors();
		}

		std::cout << "CA: certificate generated successfully\n";

		save_cert(cert);
	}

public: 
	CA(RCA* _rca) : rca(_rca) {
		generate_evp_pkey(2048);
		generate_rca_signed_cert();
	}
	void generate_evp_pkey(unsigned int bits) {
		pkey = EVP_RSA_gen(bits);
		if (!pkey) {
			std::cerr << "CA: ERV_RSA_gen error\n";
			_handle_errors();
		}
		std::cout << "CA: evp_pkey was made\n";
		save_evp_pkey(pkey);
	}

	X509* sign_cert_req(X509_REQ* cert_req) {
		if (!cert_req) {
			std::cerr << "CA: x509_req is null";
			return nullptr;
		}

		X509* signed_cert = X509_new();
		if (!signed_cert) {
			std::cerr << "CA: sign_cert_req error(X509 wasn't created)";
			return nullptr;
		}

		ASN1_INTEGER_set(X509_get_serialNumber(signed_cert), counter++);

		X509_gmtime_adj(X509_get_notBefore(signed_cert), 0);
		X509_gmtime_adj(X509_get_notAfter(signed_cert), 60 * 60 * 24 * 365);

		EVP_PKEY* req_pkey = X509_REQ_get_pubkey(cert_req);
		if (!req_pkey) {
			std::cerr << "CA: Error: Unable to get public key from certificate request." << std::endl;
			X509_free(signed_cert);
			return nullptr;
		}
		X509_set_pubkey(signed_cert, req_pkey);
		EVP_PKEY_free(req_pkey);


		X509_NAME* name = X509_REQ_get_subject_name(cert_req);
		if (!name) {
			std::cerr << "Error: X509_REQ_get_subject_name returned null." << std::endl;
			return nullptr;
		}

		if (!X509_set_subject_name(signed_cert, name)) {
			std::cerr << "ERror: can't set subject name into cert\n";
			return nullptr;
		}
		X509_set_issuer_name(signed_cert, X509_get_subject_name(cert));

		if (!X509_sign(signed_cert, pkey, EVP_sha256())) {
			std::cerr << "CA: Error: Failed to sign the certificate." << std::endl;
			X509_free(signed_cert);
			return nullptr;
		}

		std::cout << "CA: cert signed successfully\n";
		print_certificate_info(signed_cert);
		return signed_cert;
	}


	bool is_cert_verified(X509* x509) {
		if (!x509) {
			std::cerr << "CA verify: certificate is NULL\n";
			return false;
		}
		if (X509_verify(x509, X509_get_pubkey(cert)) != 1) {
			std::cerr << "Certificate signature verification failed.\n";
			return false;
		}
		ASN1_TIME* before = X509_get_notBefore(cert);
		ASN1_TIME* after = X509_get_notAfter(cert);
		if (X509_cmp_current_time(before) > 0 || X509_cmp_current_time(after) < 0) {
			std::cerr << "Certificate has expired or is not yet valid.\n";
			return false;
		}

		X509_STORE* store = X509_STORE_new();
		if (!store) {
			std::cerr << "CA verify: store creation error\n";
			return false;
		}

		if (X509_STORE_add_cert(store, rca->get_RCA_cert()) != 1) {
			std::cerr << "CA verify: store addition error\n";
			X509_STORE_free(store);
			_handle_errors();
			return false;
		}


		X509_STORE_CTX* ctx = X509_STORE_CTX_new();
		if (!ctx) {
			std::cerr << "CA verify: store context creation error\n";
			X509_STORE_free(store);
			_handle_errors();
			return false;
		}

		if (X509_STORE_CTX_init(ctx, store, x509, NULL) != 1) {
			std::cerr << "CA verify: store_ctx init error\n";
			X509_STORE_free(store);
			X509_STORE_CTX_free(ctx);
			_handle_errors();
			return false;
		}

		int result = X509_verify_cert(ctx);

		X509_STORE_free(store);
		X509_STORE_CTX_free(ctx);

		if (result != 1) {
			std::cout << "CA verify: cert isn't valid\n";
			return false;
		}

		std::cout << "CA verify: cert is valid\n";

		return true;

	}
	~CA() {
		rca->~RCA();
		EVP_PKEY_free(pkey);
		X509_free(cert);
	}
};

#endif