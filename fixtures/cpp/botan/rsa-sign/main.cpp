#include <botan/rsa.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <string>
#include <vector>

int main() {
    Botan::AutoSeeded_RNG rng;
    std::string message = "Hello, World!";
    
    // Generate RSA key pair
    Botan::RSA_PrivateKey private_key(rng, 2048);
    
    // Sign
    Botan::PK_Signer signer(private_key, rng, "EMSA-PSS(SHA-256)");
    signer.update((const uint8_t*)message.data(), message.size());
    std::vector<uint8_t> signature = signer.signature(rng);
    
    // Verify
    Botan::PK_Verifier verifier(private_key, "EMSA-PSS(SHA-256)");
    verifier.update((const uint8_t*)message.data(), message.size());
    bool valid = verifier.check_signature(signature);
    
    return valid ? 0 : 1;
}
