#ifndef CERTIFICATE_H
#define CERTIFICATE_H

#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

typedef struct {
  X509 *cert;
  EVP_PKEY *key;
} cert_pair;

static inline int set_random_serial(X509 *cert) {
  unsigned char serial_bytes[16];
  if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
    return 0;
  }
  serial_bytes[0] &= 0x7F;

  ASN1_INTEGER *ai = X509_get_serialNumber(cert);
  BIGNUM *bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
  if (!bn)
    return 0;
  int ok = BN_to_ASN1_INTEGER(bn, ai) != NULL;
  BN_free(bn);
  return ok;
}

static inline EVP_PKEY *generate_leaf_key() {
  EVP_PKEY *pkey = EVP_PKEY_new();
  RSA *rsa = RSA_new();
  BIGNUM *e = BN_new();

  BN_set_word(e, RSA_F4); // 65537
  RSA_generate_key_ex(rsa, 2048, e, NULL);

  EVP_PKEY_assign_RSA(pkey, rsa);

  BN_free(e);
  return pkey;
}

static inline void add_ext(X509 *cert, int nid, const char *value) {
  X509_EXTENSION *ex;
  X509V3_CTX ctx;

  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
  ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
  if (ex) {
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
  }
}

static inline cert_pair generate_leaf_cert(const char *hostname,
                                           EVP_PKEY *ca_key, X509 *ca_cert) {
  cert_pair out;
  out.cert = NULL;
  out.key = NULL;

  EVP_PKEY *leaf_key = generate_leaf_key();
  X509 *cert = X509_new();
  if (!cert)
    return out;

  X509_set_version(cert, 2);

  // Serial number
  if (!set_random_serial(cert)) {
    fprintf(stderr, "Failed to set random serial\n");
    X509_free(cert);
    EVP_PKEY_free(leaf_key);
    return out;
  }
  // ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)rand());

  // Validity: 5 min ago → +365 days
  X509_gmtime_adj(X509_get_notBefore(cert), -300);
  X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * 365);

  // Subject name
  X509_NAME *subj = X509_NAME_new();
  X509_NAME_add_entry_by_txt(subj, "CN", MBSTRING_ASC,
                             (unsigned char *)hostname, -1, -1, 0);
  X509_set_subject_name(cert, subj);
  X509_NAME_free(subj);

  // Issuer
  X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

  // Public key of leaf certificate
  X509_set_pubkey(cert, leaf_key);

  // X509 extensions

  // SAN
  char san_string[512];
  snprintf(san_string, sizeof(san_string), "DNS:%s", hostname);
  add_ext(cert, NID_subject_alt_name, san_string);
  add_ext(cert, NID_basic_constraints, "CA:FALSE");
  add_ext(cert, NID_key_usage, "digitalSignature,keyEncipherment");
  add_ext(cert, NID_ext_key_usage, "serverAuth");
  add_ext(cert, NID_authority_key_identifier, "keyid:always");
  add_ext(cert, NID_subject_key_identifier, "hash");

  if (!X509_sign(cert, ca_key, EVP_sha256())) {
    fprintf(stderr, "X509_sign failed\n");
    X509_free(cert);
    EVP_PKEY_free(leaf_key);
    return out;
  }

  out.cert = cert;
  out.key = leaf_key;
  return out;
}

#endif
