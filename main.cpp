#define _CRT_SECURE_NO_WARNINGS

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/applink.c>    // Для корректной работы openssl в Windows консоли
#include <openssl/core_names.h> // Для EVP_PKEY_CTX_new_from_name (OpenSSL 3.0)

#include <cstring>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <limits>
#include <ctime>
#include <locale.h>

//=============================================================
// Деаллокаторы (deleters) для объектов OpenSSL
//=============================================================
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct X509_Deleter {
    void operator()(X509* x) const { X509_free(x); }
};
struct X509_REQ_Deleter {
    void operator()(X509_REQ* r) const { X509_REQ_free(r); }
};
struct X509_CRL_Deleter {
    void operator()(X509_CRL* c) const { X509_CRL_free(c); }
};

//=============================================================
// Структуры для CA (Root, Sub) и RA
//=============================================================
struct CAInfo {
    std::string name;           // Common Name
    std::string specialization; // (для Sub CA: "TLS", "Email" и т.д.)
    bool isRoot = false;
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey;
    std::unique_ptr<X509, X509_Deleter>         cert;
    std::unique_ptr<X509_CRL, X509_CRL_Deleter> crl;
    long nextSerial = 0;
};
static std::unique_ptr<CAInfo> g_rootCA;  // Root CA
static std::vector<CAInfo>     g_subCAs;  // Sub CA

struct RAInfo {
    std::string name;        // CN
    std::string description; // Произвольное описание
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey;
    std::unique_ptr<X509, X509_Deleter>         cert;
};
static std::vector<RAInfo> g_RAs;

//=============================================================
// Пароль для PEM-файлов с приватными ключами
//=============================================================
static const char* g_keyPass = "MySuperSecret";

//=============================================================
// Генерация RSA-ключа (OpenSSL 3.0)
//=============================================================
std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> generateRSAKey(int bits)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if (!ctx) {
        std::cerr << "EVP_PKEY_CTX_new_from_name(RSA) failed.\n";
        return nullptr;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "EVP_PKEY_keygen_init() failed.\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        std::cerr << "EVP_PKEY_CTX_set_rsa_keygen_bits() failed.\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx, &raw) <= 0) {
        std::cerr << "EVP_PKEY_keygen() failed.\n";
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);

    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(raw);
}

//=============================================================
// Сохранить приватный ключ в PEM (зашифров.) -> private_keys/<...>.key
//=============================================================
bool savePrivateKeyPEM(const std::string& fileBaseName, EVP_PKEY* pkey)
{
    // Собираем полный путь: "private_keys/<fileBaseName>"
    std::string fullpath = "private_keys/" + fileBaseName;
    FILE* fp = fopen(fullpath.c_str(), "wb");
    if (!fp) {
        std::cerr << "Cannot open " << fullpath << "\n";
        return false;
    }
    const EVP_CIPHER* cipher = EVP_des_ede3_cbc();
    if (!PEM_write_PrivateKey(fp, pkey, cipher,
        (unsigned char*)g_keyPass,
        (int)strlen(g_keyPass),
        nullptr, nullptr))
    {
        std::cerr << "PEM_write_PrivateKey() failed.\n";
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

//=============================================================
// Сохранить сертификат PEM (в текущем каталоге, *.crt)
//=============================================================
bool saveCertificatePEM(const std::string& filename, X509* cert)
{
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp) {
        std::cerr << "Cannot open " << filename << "\n";
        return false;
    }
    if (!PEM_write_X509(fp, cert)) {
        std::cerr << "PEM_write_X509() failed.\n";
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

//=============================================================
// Создать самоподписанный сертификат (Root CA)
//=============================================================
std::unique_ptr<X509, X509_Deleter> createSelfSignedCert(EVP_PKEY* pkey,
    const std::string& cn,
    int daysValid = 3650)
{
    std::unique_ptr<X509, X509_Deleter> x(X509_new());
    if (!x) {
        std::cerr << "X509_new() failed.\n";
        return nullptr;
    }
    X509_set_version(x.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 1);

    X509_gmtime_adj(X509_get_notBefore(x.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x.get()), (long)daysValid * 24 * 60 * 60);

    X509_set_pubkey(x.get(), pkey);

    // subject+issuer
    X509_NAME* nm = X509_get_subject_name(x.get());
    X509_NAME_add_entry_by_txt(nm, "C", MBSTRING_ASC, (const unsigned char*)"RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC, (const unsigned char*)"MyRootCA_Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char*)cn.c_str(), -1, -1, 0);
    // issuer = subject (self-signed)
    X509_set_issuer_name(x.get(), nm);

    // Basic Constraints: CA=TRUE
    X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, nullptr,
        NID_basic_constraints,
        (char*)"critical,CA:TRUE");
    if (e) {
        X509_add_ext(x.get(), e, -1);
        X509_EXTENSION_free(e);
    }

    // Подпись
    if (!X509_sign(x.get(), pkey, EVP_sha256())) {
        std::cerr << "X509_sign(self-signed) failed.\n";
        return nullptr;
    }
    return x;
}

//=============================================================
// Создать CSR для SubCA, RA, User. 
// Здесь — 2 варианта: user=TRUE => поля C,ST,L,O,OU,email, или упрощённо CN
// Для простоты сделаем отдельную функцию "createUserCSR"
//=============================================================

// Упрощённый CSR (только CN)
std::unique_ptr<X509_REQ, X509_REQ_Deleter> createCSR(EVP_PKEY* pkey,
    const std::string& cn)
{
    std::unique_ptr<X509_REQ, X509_REQ_Deleter> req(X509_REQ_new());
    if (!req) {
        std::cerr << "X509_REQ_new() fail.\n";
        return nullptr;
    }
    X509_REQ_set_pubkey(req.get(), pkey);

    X509_NAME* nm = X509_NAME_new();
    // Поставим C=RU, O=PKI_Org, CN = переданный
    X509_NAME_add_entry_by_txt(nm, "C", MBSTRING_ASC, (const unsigned char*)"RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC, (const unsigned char*)"PKI_Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char*)cn.c_str(), -1, -1, 0);
    X509_REQ_set_subject_name(req.get(), nm);
    X509_NAME_free(nm);

    if (!X509_REQ_sign(req.get(), pkey, EVP_sha256())) {
        std::cerr << "X509_REQ_sign() fail.\n";
        return nullptr;
    }
    return req;
}

// "Расширенный" CSR для пользователя (C, ST, L, O, OU, CN, email)
std::unique_ptr<X509_REQ, X509_REQ_Deleter> createUserCSR(EVP_PKEY* pkey,
    const std::string& c,
    const std::string& st,
    const std::string& l,
    const std::string& o,
    const std::string& ou,
    const std::string& cn,
    const std::string& email)
{
    std::unique_ptr<X509_REQ, X509_REQ_Deleter> req(X509_REQ_new());
    if (!req) {
        std::cerr << "X509_REQ_new() fail.\n";
        return nullptr;
    }
    X509_REQ_set_pubkey(req.get(), pkey);

    X509_NAME* nm = X509_NAME_new();
    if (!c.empty())
        X509_NAME_add_entry_by_txt(nm, "C", MBSTRING_ASC, (const unsigned char*)c.c_str(), -1, -1, 0);
    if (!st.empty())
        X509_NAME_add_entry_by_txt(nm, "ST", MBSTRING_ASC, (const unsigned char*)st.c_str(), -1, -1, 0);
    if (!l.empty())
        X509_NAME_add_entry_by_txt(nm, "L", MBSTRING_ASC, (const unsigned char*)l.c_str(), -1, -1, 0);
    if (!o.empty())
        X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC, (const unsigned char*)o.c_str(), -1, -1, 0);
    if (!ou.empty())
        X509_NAME_add_entry_by_txt(nm, "OU", MBSTRING_ASC, (const unsigned char*)ou.c_str(), -1, -1, 0);
    if (!cn.empty())
        X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char*)cn.c_str(), -1, -1, 0);
    if (!email.empty())
        X509_NAME_add_entry_by_txt(nm, "emailAddress", MBSTRING_ASC, (const unsigned char*)email.c_str(), -1, -1, 0);

    X509_REQ_set_subject_name(req.get(), nm);
    X509_NAME_free(nm);

    if (!X509_REQ_sign(req.get(), pkey, EVP_sha256())) {
        std::cerr << "X509_REQ_sign() fail.\n";
        return nullptr;
    }
    return req;
}

//=============================================================
// Подписать CSR -> X.509 (CA=TRUE/FALSE)
//=============================================================
std::unique_ptr<X509, X509_Deleter> signCSR(EVP_PKEY* caKey,
    X509* caCert,
    X509_REQ* csr,
    long serial,
    bool isCA,
    int daysValid = 365)
{
    std::unique_ptr<X509, X509_Deleter> x(X509_new());
    if (!x) {
        std::cerr << "X509_new() fail.\n";
        return nullptr;
    }
    X509_set_version(x.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x.get()), serial);

    X509_gmtime_adj(X509_get_notBefore(x.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x.get()), (long)daysValid * 24 * 60 * 60);

    // Публичный ключ из CSR
    EVP_PKEY* pub = X509_REQ_get_pubkey(csr);
    X509_set_pubkey(x.get(), pub);
    EVP_PKEY_free(pub);

    // Subject
    X509_NAME* subj = X509_REQ_get_subject_name(csr);
    X509_set_subject_name(x.get(), subj);

    // Issuer = CA
    X509_NAME* iname = X509_get_subject_name(caCert);
    X509_set_issuer_name(x.get(), iname);

    // Basic Constraints
    if (isCA) {
        X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, nullptr,
            NID_basic_constraints,
            (char*)"critical,CA:TRUE,pathlen:0");
        if (e) {
            X509_add_ext(x.get(), e, -1);
            X509_EXTENSION_free(e);
        }
    }
    else {
        X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, nullptr,
            NID_basic_constraints,
            (char*)"critical,CA:FALSE");
        if (e) {
            X509_add_ext(x.get(), e, -1);
            X509_EXTENSION_free(e);
        }
    }

    // Подписываем
    if (!X509_sign(x.get(), caKey, EVP_sha256())) {
        std::cerr << "X509_sign(CSR) fail.\n";
        return nullptr;
    }
    return x;
}

//=============================================================
// CRL
//=============================================================
std::unique_ptr<X509_CRL, X509_CRL_Deleter> createEmptyCRL(X509* caCert)
{
    std::unique_ptr<X509_CRL, X509_CRL_Deleter> crl(X509_CRL_new());
    if (!crl) {
        std::cerr << "X509_CRL_new() fail.\n";
        return nullptr;
    }
    X509_NAME* nm = X509_get_subject_name(caCert);
    X509_CRL_set_issuer_name(crl.get(), nm);

    ASN1_TIME* now = ASN1_TIME_set(nullptr, time(nullptr));
    X509_CRL_set_lastUpdate(crl.get(), now);
    ASN1_TIME_free(now);

    ASN1_TIME* nxt = ASN1_TIME_adj(nullptr, time(nullptr), 365, 0);
    X509_CRL_set_nextUpdate(crl.get(), nxt);
    ASN1_TIME_free(nxt);

    return crl;
}

bool saveCRL_PEM(const std::string& filename, X509_CRL* crl)
{
    FILE* f = fopen(filename.c_str(), "wb");
    if (!f) {
        std::cerr << "Cannot open " << filename << "\n";
        return false;
    }
    if (!PEM_write_X509_CRL(f, crl)) {
        std::cerr << "PEM_write_X509_CRL() fail.\n";
        fclose(f);
        return false;
    }
    fclose(f);
    return true;
}
bool signCRL(X509_CRL* crl, EVP_PKEY* caKey)
{
    if (!X509_CRL_sign(crl, caKey, EVP_sha256())) {
        std::cerr << "X509_CRL_sign() fail.\n";
        return false;
    }
    return true;
}
bool revokeCertInCRL(X509_CRL* crl, const std::string& serialHex)
{
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, serialHex.c_str());
    ASN1_INTEGER* asn = ASN1_INTEGER_new();
    BN_to_ASN1_INTEGER(bn, asn);

    X509_REVOKED* rv = X509_REVOKED_new();
    X509_REVOKED_set_serialNumber(rv, asn);

    ASN1_TIME* revTime = ASN1_TIME_set(nullptr, time(nullptr));
    X509_REVOKED_set_revocationDate(rv, revTime);
    ASN1_TIME_free(revTime);

    if (!X509_CRL_add0_revoked(crl, rv)) {
        std::cerr << "X509_CRL_add0_revoked() fail.\n";
        X509_REVOKED_free(rv);
        ASN1_INTEGER_free(asn);
        BN_free(bn);
        return false;
    }
    ASN1_INTEGER_free(asn);
    BN_free(bn);
    return true;
}

//=============================================================
// Проверка цепочки + CRL
//=============================================================
bool verifyCertificate(const std::string& certFile,
    const CAInfo& root,
    const std::vector<CAInfo>& subs)
{
    // Открываем файл certFile
    FILE* f = fopen(certFile.c_str(), "rb");
    if (!f) {
        std::cerr << "Cannot open " << certFile << "\n";
        return false;
    }
    X509* x = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!x) {
        std::cerr << "PEM_read_X509() fail.\n";
        return false;
    }

    X509_STORE* store = X509_STORE_new();
    if (!store) {
        X509_free(x);
        return false;
    }
    // Root CA + CRL
    X509_STORE_add_cert(store, root.cert.get());
    if (root.crl) {
        X509_STORE_add_crl(store, root.crl.get());
    }
    // Sub CA + CRLs
    for (const auto& sca : subs) {
        X509_STORE_add_cert(store, sca.cert.get());
        if (sca.crl) {
            X509_STORE_add_crl(store, sca.crl.get());
        }
    }
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_free(x);
        X509_STORE_free(store);
        return false;
    }
    if (!X509_STORE_CTX_init(ctx, store, x, nullptr)) {
        X509_free(x);
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return false;
    }

    int ret = X509_verify_cert(ctx);
    if (ret == 1) {
        std::cout << "Сертификат " << certFile << " проверен успешно!\n";
    }
    else {
        int err = X509_STORE_CTX_get_error(ctx);
        std::cerr << "Ошибка проверки: " << X509_verify_cert_error_string(err)
            << " (code=" << err << ")\n";
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(x);
    return (ret == 1);
}

//=============================================================
// Извлечь серийный номер (hex) из .crt
//=============================================================
std::string getCertSerialHex(const std::string& certFile)
{
    FILE* f = fopen(certFile.c_str(), "rb");
    if (!f) {
        std::cerr << "Cannot open " << certFile << "\n";
        return "";
    }
    X509* c = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!c) {
        std::cerr << "PEM_read_X509() fail.\n";
        return "";
    }
    ASN1_INTEGER* sn = X509_get_serialNumber(c);
    BIGNUM* bn = ASN1_INTEGER_to_BN(sn, nullptr);
    char* hex = BN_bn2hex(bn);
    std::string res = (hex ? hex : "");
    BN_free(bn);
    if (hex) OPENSSL_free(hex);
    X509_free(c);
    return res;
}

//=============================================================
// Меню
//=============================================================

// Выбрать CA (Root или Sub)
CAInfo* chooseCA()
{
    if (!g_rootCA) {
        std::cout << "Root CA не создан.\n";
        return nullptr;
    }
    std::cout << "Выберите CA:\n";
    std::cout << "  0) Root CA: " << g_rootCA->name << "\n";
    for (size_t i = 0; i < g_subCAs.size(); i++) {
        std::cout << "  " << (i + 1) << ") Sub CA: " << g_subCAs[i].name
            << " (" << g_subCAs[i].specialization << ")\n";
    }
    std::cout << "Ваш выбор: ";
    int c;
    if (!(std::cin >> c)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cerr << "Некорректный ввод.\n";
        return nullptr;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    if (c == 0) return g_rootCA.get();
    else if (c > 0 && (size_t)c <= g_subCAs.size()) {
        return &g_subCAs[c - 1];
    }
    std::cout << "Неверный выбор.\n";
    return nullptr;
}

// 1) Создать Root CA
void menuCreateRootCA()
{
    if (g_rootCA) {
        std::cout << "Root CA уже существует.\n";
        return;
    }
    std::cout << "Введите Common Name (CN) для Root CA: ";
    std::string cn;
    std::getline(std::cin, cn);
    if (cn.empty()) {
        std::cout << "Отмена.\n";
        return;
    }
    std::cout << "Длина ключа Root CA (2048..4096..): ";
    int bits;
    if (!(std::cin >> bits)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        bits = 4096;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    auto rootKey = generateRSAKey(bits);
    if (!rootKey) {
        std::cerr << "Ошибка генерации RootKey.\n";
        return;
    }
    auto rootCert = createSelfSignedCert(rootKey.get(), cn, 3650);
    if (!rootCert) {
        std::cerr << "Ошибка createSelfSignedCert.\n";
        return;
    }

    // Сохраним: ключ -> private_keys/rootCA_enc.key, сертификат -> rootCA_cert.crt
    savePrivateKeyPEM("rootCA_enc.key", rootKey.get());
    saveCertificatePEM("rootCA_cert.crt", rootCert.get());

    auto crl = createEmptyCRL(rootCert.get());
    if (crl) {
        signCRL(crl.get(), rootKey.get());
        saveCRL_PEM("rootCA_crl.crl", crl.get());
    }

    g_rootCA = std::make_unique<CAInfo>();
    g_rootCA->name = cn;
    g_rootCA->isRoot = true;
    g_rootCA->pkey = std::move(rootKey);
    g_rootCA->cert = std::move(rootCert);
    g_rootCA->crl = std::move(crl);
    g_rootCA->nextSerial = 100;

    std::cout << "Root CA создан: private_keys/rootCA_enc.key, rootCA_cert.crt, rootCA_crl.crl\n";
}

// 2) Создать Sub CA
void menuCreateSubCA()
{
    if (!g_rootCA) {
        std::cout << "Нет Root CA.\n";
        return;
    }
    std::cout << "CN Sub CA: ";
    std::string cn;
    std::getline(std::cin, cn);
    if (cn.empty()) return;

    std::cout << "Специализация Sub CA (TLS, Email...): ";
    std::string spec;
    std::getline(std::cin, spec);

    std::cout << "Длина ключа Sub CA (2048..4096..): ";
    int bits;
    if (!(std::cin >> bits)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        bits = 2048;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    auto subKey = generateRSAKey(bits);
    auto csr = createCSR(subKey.get(), cn);
    long serial = g_rootCA->nextSerial++;
    auto subCert = signCSR(g_rootCA->pkey.get(), g_rootCA->cert.get(),
        csr.get(), serial, true, 3650);

    // Сохраняем
    std::string keyFile = cn + "_enc.key";
    std::string crtFile = cn + "_cert.crt";

    savePrivateKeyPEM(keyFile, subKey.get());
    saveCertificatePEM(crtFile, subCert.get());

    auto crl = createEmptyCRL(subCert.get());
    if (crl) {
        signCRL(crl.get(), subKey.get());
        std::string crlFile = cn + "_crl.crl";
        saveCRL_PEM(crlFile, crl.get());
    }

    CAInfo info;
    info.name = cn;
    info.specialization = spec;
    info.isRoot = false;
    info.pkey = std::move(subKey);
    info.cert = std::move(subCert);
    info.crl = std::move(crl);
    info.nextSerial = 1000;

    g_subCAs.push_back(std::move(info));
    std::cout << "Sub CA создан: private_keys/" << keyFile << ", "
        << crtFile << "\n";
}

// 3) Создать RA
void menuCreateRA()
{
    if (!g_rootCA) {
        std::cout << "Нет Root CA.\n";
        return;
    }
    std::cout << "CN RA: ";
    std::string cn;
    std::getline(std::cin, cn);
    if (cn.empty()) return;

    std::cout << "Описание RA (прим. Main office RA): ";
    std::string desc;
    std::getline(std::cin, desc);

    std::cout << "Длина ключа RA (2048..4096..): ";
    int bits;
    if (!(std::cin >> bits)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        bits = 2048;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    auto raKey = generateRSAKey(bits);
    auto csr = createCSR(raKey.get(), cn);
    long serial = g_rootCA->nextSerial++;
    auto raCert = signCSR(g_rootCA->pkey.get(), g_rootCA->cert.get(),
        csr.get(), serial, false, 365);

    // Сохраняем
    std::string keyFile = cn + "_enc.key";
    std::string crtFile = cn + "_cert.crt";
    savePrivateKeyPEM(keyFile, raKey.get());
    saveCertificatePEM(crtFile, raCert.get());

    RAInfo r;
    r.name = cn;
    r.description = desc;
    r.pkey = std::move(raKey);
    r.cert = std::move(raCert);
    g_RAs.push_back(std::move(r));

    std::cout << "RA создан: private_keys/" << keyFile << ", "
        << crtFile << ", описание='" << desc << "'\n";
}

// 4) Создать сертификат пользователя (End Entity) c расширенными полями
void menuCreateUserCertificate()
{
    CAInfo* signer = chooseCA();
    if (!signer) return;

    // Запрашиваем поля: C, ST, L, O, OU, CN, email
    std::string c, st, l, o, ou, cn, email;
    std::cout << "Country (C): ";       std::getline(std::cin, c);
    std::cout << "State (ST): ";        std::getline(std::cin, st);
    std::cout << "Locality (L): ";      std::getline(std::cin, l);
    std::cout << "Organization (O): ";  std::getline(std::cin, o);
    std::cout << "OrgUnit (OU): ";      std::getline(std::cin, ou);
    std::cout << "CommonName (CN): ";   std::getline(std::cin, cn);
    std::cout << "Email: ";            std::getline(std::cin, email);

    std::cout << "Длина ключа пользователя (2048..4096..): ";
    int bits;
    if (!(std::cin >> bits)) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        bits = 2048;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    // Генерируем ключ
    auto userKey = generateRSAKey(bits);
    if (!userKey) {
        std::cerr << "Ошибка генерации userKey.\n";
        return;
    }

    // Создаём CSR c расширенными полями
    auto req = createUserCSR(userKey.get(), c, st, l, o, ou, cn, email);
    if (!req) {
        std::cerr << "Ошибка createUserCSR.\n";
        return;
    }

    long serial = signer->nextSerial++;
    auto userCert = signCSR(signer->pkey.get(), signer->cert.get(),
        req.get(), serial, false, 365);
    if (!userCert) {
        std::cerr << "Ошибка signCSR(user).\n";
        return;
    }

    std::string keyFile = cn + "_enc.key";
    std::string crtFile = cn + "_cert.crt";
    // Сохраняем в папку private_keys
    savePrivateKeyPEM(keyFile, userKey.get());
    saveCertificatePEM(crtFile, userCert.get());

    std::cout << "Пользовательский сертификат выпущен: "
        << "private_keys/" << keyFile << " (зашифр.), "
        << crtFile << "\n";
}

// 5) Отозвать сертификат
void menuRevokeCertificate()
{
    CAInfo* ca = chooseCA();
    if (!ca) return;
    if (!ca->crl) {
        std::cerr << "У этого CA нет CRL.\n";
        return;
    }
    std::cout << "Укажите .crt (сертификат) для отзыва: ";
    std::string certFile;
    std::getline(std::cin, certFile);
    if (certFile.empty()) return;

    // Извлечём серийник
    FILE* f = fopen(certFile.c_str(), "rb");
    if (!f) {
        std::cerr << "Cannot open " << certFile << "\n";
        return;
    }
    X509* x = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!x) {
        std::cerr << "PEM_read_X509() fail.\n";
        return;
    }
    BIGNUM* bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x), nullptr);
    char* hex = BN_bn2hex(bn);
    std::string serHex = (hex ? hex : "");
    BN_free(bn);
    if (hex) OPENSSL_free(hex);
    X509_free(x);

    if (serHex.empty()) {
        std::cerr << "Не удалось извлечь серийный номер.\n";
        return;
    }
    if (!revokeCertInCRL(ca->crl.get(), serHex)) {
        std::cerr << "Ошибка revokeCertInCRL.\n";
        return;
    }

    // Переподпишем CRL
    ASN1_TIME* now = ASN1_TIME_set(nullptr, time(nullptr));
    X509_CRL_set_lastUpdate(ca->crl.get(), now);
    ASN1_TIME_free(now);

    if (!signCRL(ca->crl.get(), ca->pkey.get())) {
        std::cerr << "Ошибка подписи CRL.\n";
        return;
    }
    std::string crlFile = (ca->isRoot ? "rootCA_crl.crl" : ca->name + "_crl.crl");
    saveCRL_PEM(crlFile, ca->crl.get());

    std::cout << "Сертификат отозван (serial=" << serHex
        << "), CRL обновлён: " << crlFile << "\n";
}

// 6) Проверить сертификат
void menuCheckCertificate()
{
    if (!g_rootCA) {
        std::cout << "Root CA не создан.\n";
        return;
    }
    std::cout << "Укажите .crt для проверки: ";
    std::string fname;
    std::getline(std::cin, fname);
    if (fname.empty()) return;

    verifyCertificate(fname, *g_rootCA, g_subCAs);
}

// 7) Показать структуру
void menuShowStructure()
{
    std::cout << "\n====== Структура ИОК ======\n";
    if (!g_rootCA) {
        std::cout << "(Root CA не создан)\n";
    }
    else {
        std::cout << "[Root CA] " << g_rootCA->name
            << " (nextSerial=" << g_rootCA->nextSerial << ")\n";
    }
    for (auto& sca : g_subCAs) {
        std::cout << "  [Sub CA] " << sca.name
            << " (spec=" << sca.specialization << ", nextSerial="
            << sca.nextSerial << ")\n";
    }
    for (auto& r : g_RAs) {
        std::cout << "  [RA] " << r.name
            << " (desc=" << r.description << ")\n";
    }
    std::cout << "==========================\n";
}

//=============================================================
// main
//=============================================================
int main()
{
    std::setlocale(LC_ALL, "rus");

    // Инициализация OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Тут можно создать папку private_keys, если она не существует.
    // Для этого можно использовать mkdir(…).
    // Опустим в данном примере.

    while (true) {
        std::cout << "\n========= PKI Manager =========\n"
            << "1) Создать Root CA\n"
            << "2) Создать Sub CA\n"
            << "3) Создать RA\n"
            << "4) Создать сертификат пользователя\n"
            << "5) Отозвать сертификат\n"
            << "6) Проверить сертификат\n"
            << "7) Показать структуру\n"
            << "0) Выход\n"
            << "=======================================\n"
            << "Ваш выбор: ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cerr << "Некорректный ввод.\n";
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
        case 0:
            std::cout << "Выход.\n";
            // Освобождение OpenSSL
            EVP_cleanup();
            CRYPTO_cleanup_all_ex_data();
            ERR_free_strings();
            return 0;

        case 1:
            menuCreateRootCA();
            break;
        case 2:
            menuCreateSubCA();
            break;
        case 3:
            menuCreateRA();
            break;
        case 4:
            menuCreateUserCertificate();
            break;
        case 5:
            menuRevokeCertificate();
            break;
        case 6:
            menuCheckCertificate();
            break;
        case 7:
            menuShowStructure();
            break;
        default:
            std::cerr << "Неверный пункт.\n";
            break;
        }
    }

    return 0;
}
