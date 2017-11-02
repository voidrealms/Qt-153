#include "cipher.h"

Cipher::Cipher(QObject *parent) : QObject(parent)
{
    initalize();
}

Cipher::~Cipher()
{
    finalize();
}

RSA *Cipher::getPublicKey(QByteArray &data)
{
    const char* publicKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio,NULL, NULL, NULL);
    if(!rsaPubKey)
    {
        qCritical() << "Could not load public key" << ERR_error_string(ERR_get_error(),NULL);
    }

    BIO_free(bio);
    return rsaPubKey;

}

RSA *Cipher::getPublicKey(QString filename)
{
    QByteArray data = readFile(filename);

    return getPublicKey(data);
}

RSA *Cipher::getPrivateKey(QByteArray &data)
{
    const char* privateKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)privateKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio,NULL, NULL, NULL);
    if(!rsaPrivKey)
    {
        qCritical() << "Could not load private key" << ERR_error_string(ERR_get_error(),NULL);
    }

    BIO_free(bio);
    return rsaPrivKey;
}

RSA *Cipher::getPrivateKey(QString filename)
{
    QByteArray data = readFile(filename);

    return getPrivateKey(data);
}

QByteArray Cipher::encryptRSA(RSA *key, QByteArray &data)
{
    QByteArray buffer;
    int dataSize = data.length();
    const unsigned char* str = (const unsigned char*)data.constData();
    int rsaLen = RSA_size(key);

    unsigned char* ed = (unsigned char*)malloc(rsaLen);
    // RSA_private_encrypt() - if you are encrypting with the private key
    int resultLen = RSA_public_encrypt(dataSize, (const unsigned char*)str, ed, key, PADDING);

    if(resultLen == -1)
    {
        qCritical() << "Could not encrypt: " << ERR_error_string(ERR_get_error(),NULL);
        return buffer;
    }

    buffer = QByteArray(reinterpret_cast<char*>(ed), resultLen);
    free(ed);

    return buffer;

}

QByteArray Cipher::decryptRSA(RSA *key, QByteArray &data)
{
    QByteArray buffer;
    const unsigned char* encryptedData = (const unsigned char*)data.constData();

    int rsaLen = RSA_size(key);

    unsigned char* ed = (unsigned char*)malloc(rsaLen);
    //RSA_public_decrypt() - if you are using the public key
    int resultLen = RSA_private_decrypt(rsaLen, encryptedData, ed, key, PADDING);

    if(resultLen == -1)
    {
        qCritical() << "Could not decrypt: " << ERR_error_string(ERR_get_error(),NULL);
        return buffer;
    }

    buffer = QByteArray(reinterpret_cast<char*>(ed), resultLen);
    free(ed);

    return buffer;
}

QByteArray Cipher::encryptAES(QByteArray passphrase, QByteArray &data)
{
    QByteArray msalt = randomBytes(SALTSIZE);
    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];

    const unsigned char* salt = (const unsigned char*) msalt.constData();
    const unsigned char* password = (const unsigned char*) passphrase.constData();

    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt,password, passphrase.length(),rounds,key,iv);

    if(i != KEYSIZE)
    {
        qCritical() << "EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    EVP_CIPHER_CTX en;
    EVP_CIPHER_CTX_init(&en);

    if(!EVP_EncryptInit_ex(&en, EVP_aes_256_cbc(),NULL,key, iv))
    {
        qCritical() << "EVP_EncryptInit_ex() failed " << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    char *input = data.data();
    int len = data.size();

    int c_len = len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = (unsigned char*)malloc(c_len);

    if(!EVP_EncryptInit_ex(&en, NULL, NULL, NULL, NULL))
    {
        qCritical() << "EVP_EncryptInit_ex() failed " << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    // May have to repeat this for large files

    if(!EVP_EncryptUpdate(&en, ciphertext, &c_len,(unsigned char *)input, len))
    {
        qCritical() << "EVP_EncryptUpdate() failed " << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    if(!EVP_EncryptFinal(&en, ciphertext+c_len, &f_len))
    {
        qCritical() << "EVP_EncryptFinal_ex() failed "  << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    len = c_len + f_len;
    EVP_CIPHER_CTX_cipher(&en);

    //ciphertext

    QByteArray encrypted = QByteArray(reinterpret_cast<char*>(ciphertext), len);
    QByteArray finished;
    finished.append("Salted__");
    finished.append(msalt);
    finished.append(encrypted);

    free(ciphertext);

    return finished;
}

QByteArray Cipher::decryptAES(QByteArray passphrase, QByteArray &data)
{
    QByteArray msalt;
    if(QString(data.mid(0,8)) == "Salted__")
    {
        msalt = data.mid(8,8);
        data = data.mid(16);
    }
    else
    {
        qWarning() << "Could not load salt from data!";
        msalt = randomBytes(SALTSIZE);
    }

    int rounds = 1;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];
    const unsigned char* salt = (const unsigned char*)msalt.constData();
    const unsigned char* password = (const unsigned char*)passphrase.data();

    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt,password, passphrase.length(),rounds,key,iv);

    if(i != KEYSIZE)
    {
        qCritical() << "EVP_BytesToKey() error: " << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    EVP_CIPHER_CTX de;
    EVP_CIPHER_CTX_init(&de);

    if(!EVP_DecryptInit_ex(&de,EVP_aes_256_cbc(), NULL, key,iv ))
    {
        qCritical() << "EVP_DecryptInit_ex() failed" << ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    char *input = data.data();
    int len = data.size();

    int p_len = len, f_len = 0;
    unsigned char *plaintext = (unsigned char *)malloc(p_len + AES_BLOCK_SIZE);

    //May have to do this multiple times for large data???
    if(!EVP_DecryptUpdate(&de, plaintext, &p_len, (unsigned char *)input, len))
    {
        qCritical() << "EVP_DecryptUpdate() failed " <<  ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    if(!EVP_DecryptFinal_ex(&de,plaintext+p_len,&f_len))
    {
        qCritical() << "EVP_DecryptFinal_ex() failed " <<  ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    len = p_len + f_len;

    EVP_CIPHER_CTX_cleanup(&de);


    QByteArray decrypted = QByteArray(reinterpret_cast<char*>(plaintext), len);
    free(plaintext);

    return decrypted;

}

QByteArray Cipher::randomBytes(int size)
{
    unsigned char arr[size];
    RAND_bytes(arr,size);

    QByteArray buffer = QByteArray(reinterpret_cast<char*>(arr), size);
    return buffer;
}

void Cipher::freeRSAKey(RSA *key)
{
    RSA_free(key);
}

void Cipher::initalize()
{
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void Cipher::finalize()
{
    EVP_cleanup();
    ERR_free_strings();
}

QByteArray Cipher::readFile(QString filename)
{
    QByteArray data;
    QFile file(filename);
    if(!file.open(QFile::ReadOnly))
    {
        qCritical() << file.errorString();
        return data;
    }

    data = file.readAll();
    file.close();
    return data;
}

void Cipher::writeFile(QString filename, QByteArray &data)
{
    QFile file(filename);
    if(!file.open(QFile::WriteOnly))
    {
        qCritical() << file.errorString();
        return;
    }

    file.write(data);
    file.close();
}
