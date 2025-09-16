#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <string>

int main() {
    using namespace CryptoPP;
    
    std::string message = "Hello, World!";
    byte digest[SHA256::DIGESTSIZE];
    
    SHA256 hash;
    hash.Update((const byte*)message.data(), message.size());
    hash.Final(digest);
    
    return 0;
}
