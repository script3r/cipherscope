#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <string>

int main() {
    using namespace CryptoPP;
    
    std::string key = "secret_key";
    std::string message = "Hello, World!";
    byte mac[HMAC<SHA256>::DIGESTSIZE];
    
    // Create HMAC
    HMAC<SHA256> hmac((const byte*)key.data(), key.size());
    hmac.Update((const byte*)message.data(), message.size());
    hmac.Final(mac);
    
    // Verify HMAC
    HMAC<SHA256> verifier((const byte*)key.data(), key.size());
    verifier.Update((const byte*)message.data(), message.size());
    bool valid = verifier.Verify(mac);
    
    return valid ? 0 : 1;
}
