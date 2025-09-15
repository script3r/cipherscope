#include <botan/rsa.h>
#include <botan/aead.h>
#include <botan/hash.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <iostream>

int main() {
    Botan::AutoSeeded_RNG rng;
    
    std::cout << "Testing Botan cryptographic library..." << std::endl;
    
    // RSA key generation
    Botan::RSA_PrivateKey rsa_key(rng, 2048);
    std::cout << "✓ RSA 2048-bit key pair generated" << std::endl;
    
    // AES-GCM AEAD
    auto aead = Botan::AEAD_Mode::create("AES-256/GCM", Botan::ENCRYPTION);
    if (!aead) {
        std::cerr << "Failed to create AES-GCM" << std::endl;
        return 1;
    }
    
    std::vector<uint8_t> key(32); // 256-bit key
    rng.randomize(key.data(), key.size());
    aead->set_key(key);
    
    std::cout << "✓ AES-256-GCM AEAD initialized" << std::endl;
    
    // Hash functions
    auto sha256 = Botan::HashFunction::create("SHA-256");
    auto sha3_256 = Botan::HashFunction::create("SHA-3(256)");
    auto blake2b = Botan::HashFunction::create("BLAKE2b(256)");
    
    std::string message = "Hello, Botan World!";
    std::vector<uint8_t> message_bytes(message.begin(), message.end());
    
    if (sha256) {
        sha256->update(message_bytes);
        auto hash = sha256->final();
        std::cout << "✓ SHA-256 hash computed" << std::endl;
    }
    
    if (sha3_256) {
        sha3_256->update(message_bytes);
        auto hash = sha3_256->final();
        std::cout << "✓ SHA-3-256 hash computed" << std::endl;
    }
    
    if (blake2b) {
        blake2b->update(message_bytes);
        auto hash = blake2b->final();
        std::cout << "✓ BLAKE2b hash computed" << std::endl;
    }
    
    std::cout << "\nPQC Assessment:" << std::endl;
    std::cout << "- RSA 2048-bit: VULNERABLE to quantum attacks" << std::endl;
    std::cout << "- AES-256-GCM: SAFE from quantum attacks" << std::endl;
    std::cout << "- SHA-256: SAFE from quantum attacks" << std::endl;
    std::cout << "- SHA-3-256: SAFE from quantum attacks" << std::endl;
    std::cout << "- BLAKE2b: SAFE from quantum attacks" << std::endl;
    
    return 0;
}