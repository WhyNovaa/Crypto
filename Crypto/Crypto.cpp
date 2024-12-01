#define _CRT_SECURE_NO_WARNINGS
#include <openssl/applink.c>
#include "C:\Users\novik\source\repos\Crypto\Crypto/CA.h"
#include "C:\Users\novik\source\repos\Crypto\Crypto/RCA.h"




int main() {
	RCA* rca = new RCA();
	CA* ca = new CA(rca);

	X509_REQ* req = X509_REQ_new();

	X509_NAME* name = X509_REQ_get_subject_name(req);

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*) "Google", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*) "Something", -1, -1, 0);

	if (!X509_REQ_set_subject_name(req, name)) {
		std::cerr << "Error in set subject name to request\n";
		X509_NAME_free(name);
		X509_REQ_free(req);
		return 1;
	}


	EVP_PKEY* pkey = EVP_RSA_gen(2048);

	if (!X509_REQ_set_pubkey(req, pkey)) {
		std::cerr << "Error in addition pubkey into X509_REQ\n";
		EVP_PKEY_free(pkey);
		X509_REQ_free(req);
		return 1;
	}


	/*if (!X509_REQ_sign(req, pkey, NULL)) {
		std::cerr << "Error in signing request by private key\n";
		X509_REQ_free(req);
		return 1;
	}*/

	X509* res = ca->sign_cert_req(req);




	if (!res) {
		std::cout << "Error in signing request in CA\n";
		return 1;
	}
	FILE* file = nullptr;
	fopen_s(&file, "signed_certificate.pem", "wb");
	PEM_write_X509(file, res);
	fclose(file);
	std::cout << ca->is_cert_verified(res);

}
