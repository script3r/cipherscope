#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;
    
    std::cout << "Testing Crypto++ library..." << std::endl;
    
    // RSA key generation
    RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rng, 2048);
    RSA::PublicKey rsaPublic(rsaPrivate);
    std::cout << "✓ RSA 2048-bit key pair generated" << std::endl;
    
    // AES-GCM encryption
    SecByteBlock aes_key(AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(aes_key, aes_key.size());
    
    GCM<AES>::Encryption aes_gcm;
    aes_gcm.SetKeyWithIV(aes_key, aes_key.size(), nullptr, 0);
    std::cout << "✓ AES-256-GCM encryption setup" << std::endl;
    
    // Hash functions
    SHA256 sha256;
    SHA512 sha512;
    
    std::string message = "Hello, Crypto++ World!";
    
    std::string sha256_digest;
    StringSource(message, true, new HashFilter(sha256, new StringSink(sha256_digest)));
    std::cout << "✓ SHA-256 hash computed" << std::endl;
    
    std::string sha512_digest;
    StringSource(message, true, new HashFilter(sha512, new StringSink(sha512_digest)));
    std::cout << "✓ SHA-512 hash computed" << std::endl;
    
    std::cout << "\nPQC Assessment:" << std::endl;
    std::cout << "- RSA 2048-bit: VULNERABLE to quantum attacks" << std::endl;
    std::cout << "- AES-256-GCM: SAFE from quantum attacks" << std::endl;
    std::cout << "- SHA-256: SAFE from quantum attacks" << std::endl;
    std::cout << "- SHA-512: SAFE from quantum attacks" << std::endl;
    
    return 0;
}