#include <cryptopp/rsa.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <string>

int main() {
    using namespace CryptoPP;
    
    AutoSeededRandomPool rng;
    std::string message = "Hello, World!";
    
    // Generate RSA key pair
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);
    RSA::PublicKey publicKey(privateKey);
    
    // Sign
    RSASS<PSS, SHA256>::Signer signer(privateKey);
    byte signature[signer.MaxSignatureLength()];
    size_t sigLen = signer.SignMessage(rng, 
        (const byte*)message.data(), message.size(), signature);
    
    // Verify
    RSASS<PSS, SHA256>::Verifier verifier(publicKey);
    bool valid = verifier.VerifyMessage(
        (const byte*)message.data(), message.size(), 
        signature, sigLen);
    
    return valid ? 0 : 1;
}
