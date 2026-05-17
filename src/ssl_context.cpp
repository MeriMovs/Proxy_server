#pragma once

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <shared_mutex>
#include <string>
#include <unordered_map>

class SslContext {
public:
    ~SslContext();
    bool     load_ca(const std::string& cert_path, const std::string& key_path);
    SSL_CTX* get_server_ctx(const std::string& hostname);
    SSL_CTX* get_client_ctx();
private:
    SSL_CTX*  generate_leaf_ctx(const std::string& hostname);
    static EVP_PKEY* generate_rsa_key(int bits = 2048);
    static X509*     generate_leaf_cert(const std::string& hostname,
                                        X509*     ca_cert,
                                        EVP_PKEY* ca_key,
                                        EVP_PKEY* leaf_key);

    X509*     ca_cert_{nullptr};
    EVP_PKEY* ca_key_{nullptr};
    std::unordered_map<std::string, SSL_CTX*> ctx_cache_;
    mutable std::shared_mutex                  cache_mutex_;
    SSL_CTX*  client_ctx_{nullptr};
};

// -----------------------------------------------------------------------------

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <iostream>
#include <memory>
#include <mutex>

static void log_ssl_errors(const char* context) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "[SSL] " << context << ": " << buf << "\n";
    }
}

struct X509Deleter   { void operator()(X509*     p) const { X509_free(p);     } };
struct EVPKeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct BIODeleter    { void operator()(BIO*      p) const { BIO_free(p);      } };

using UniqueX509   = std::unique_ptr<X509,    X509Deleter>;
using UniqueEVPKey = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;

SslContext::~SslContext() {
    for (auto& [host, ctx] : ctx_cache_)
        SSL_CTX_free(ctx);
    SSL_CTX_free(client_ctx_);
    X509_free(ca_cert_);
    EVP_PKEY_free(ca_key_);
}

bool SslContext::load_ca(const std::string& cert_path, const std::string& key_path) {
    std::unique_ptr<BIO, BIODeleter> cert_bio(BIO_new_file(cert_path.c_str(), "r"));
    if (!cert_bio) { std::cerr << "[SslContext] Cannot open: " << cert_path << "\n"; return false; }
    ca_cert_ = PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr);
    if (!ca_cert_) { log_ssl_errors("read CA cert"); return false; }

    std::unique_ptr<BIO, BIODeleter> key_bio(BIO_new_file(key_path.c_str(), "r"));
    if (!key_bio) { std::cerr << "[SslContext] Cannot open: " << key_path << "\n"; return false; }
    ca_key_ = PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr);
    if (!ca_key_) { log_ssl_errors("read CA key"); return false; }

    client_ctx_ = SSL_CTX_new(TLS_client_method());
    if (!client_ctx_) { log_ssl_errors("SSL_CTX_new (client)"); return false; }
    SSL_CTX_set_verify(client_ctx_, SSL_VERIFY_NONE, nullptr);
    std::cerr << "[SslContext] CA loaded from " << cert_path << "\n";
    return true;
}

SSL_CTX* SslContext::get_client_ctx() { return client_ctx_; }

SSL_CTX* SslContext::get_server_ctx(const std::string& hostname) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);
    SSL_CTX*& ctx = ctx_cache_[hostname];
    if (!ctx) ctx = generate_leaf_ctx(hostname);
    return ctx;
}

EVP_PKEY* SslContext::generate_rsa_key(int bits) {
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, bits);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

X509* SslContext::generate_leaf_cert(const std::string& hostname,
                                      X509*     ca_cert,
                                      EVP_PKEY* ca_key,
                                      EVP_PKEY* leaf_key) {
    UniqueX509 cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), (long)std::time(nullptr));
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()),  365 * 24 * 3600L);
    X509_set_pubkey(cert.get(), leaf_key);

    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(hostname.c_str()),
        static_cast<int>(hostname.size()), -1, 0);
    X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert));

    auto add_ext = [&](int nid, const char* value) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, nid, value);
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    };
    add_ext(NID_subject_alt_name,  ("DNS:" + hostname).c_str());
    add_ext(NID_basic_constraints, "CA:FALSE");
    add_ext(NID_key_usage,         "critical,digitalSignature,keyEncipherment");
    add_ext(NID_ext_key_usage,     "serverAuth");

    X509_sign(cert.get(), ca_key, EVP_sha256());
    return cert.release();
}

SSL_CTX* SslContext::generate_leaf_ctx(const std::string& hostname) {
    UniqueEVPKey leaf_key(generate_rsa_key(2048));
    UniqueX509   leaf_cert(generate_leaf_cert(hostname, ca_cert_, ca_key_, leaf_key.get()));
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, leaf_cert.get());
    SSL_CTX_use_PrivateKey(ctx, leaf_key.get());
    SSL_CTX_add_extra_chain_cert(ctx, X509_dup(ca_cert_));
    return ctx;
}
