#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <vector>
#include <string>

int main() {
    Botan::AutoSeeded_RNG rng;
    
    std::vector<uint8_t> key(32);
    std::vector<uint8_t> iv(12);
    rng.randomize(key.data(), key.size());
    rng.randomize(iv.data(), iv.size());
    
    std::string plaintext = "Hello, World!";
    
    // Encrypt
    auto enc = Botan::AEAD_Mode::create("AES-256/GCM", Botan::ENCRYPTION);
    enc->set_key(key);
    enc->start(iv);
    Botan::secure_vector<uint8_t> ciphertext((uint8_t*)plaintext.data(), 
                                             (uint8_t*)plaintext.data() + plaintext.size());
    enc->finish(ciphertext);
    
    // Decrypt
    auto dec = Botan::AEAD_Mode::create("AES-256/GCM", Botan::DECRYPTION);
    dec->set_key(key);
    dec->start(iv);
    Botan::secure_vector<uint8_t> decrypted = ciphertext;
    dec->finish(decrypted);
    
    return 0;
}
