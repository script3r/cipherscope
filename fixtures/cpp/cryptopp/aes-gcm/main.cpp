#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <string>

int main() {
    using namespace CryptoPP;
    
    byte key[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    std::string plaintext = "Hello, World!";
    std::string ciphertext, decrypted;
    
    // Encrypt
    GCM<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
    StringSource(plaintext, true,
        new AuthenticatedEncryptionFilter(encryptor,
            new StringSink(ciphertext)));
    
    // Decrypt
    GCM<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
    StringSource(ciphertext, true,
        new AuthenticatedDecryptionFilter(decryptor,
            new StringSink(decrypted)));
    
    return 0;
}
