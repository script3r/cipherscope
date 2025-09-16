#include <botan/mac.h>
#include <string>
#include <vector>

int main() {
    std::string key = "secret_key";
    std::string message = "Hello, World!";
    
    // Create HMAC
    auto hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
    hmac->set_key((const uint8_t*)key.data(), key.size());
    hmac->update((const uint8_t*)message.data(), message.size());
    std::vector<uint8_t> mac = hmac->final();
    
    // Verify HMAC
    hmac->set_key((const uint8_t*)key.data(), key.size());
    hmac->update((const uint8_t*)message.data(), message.size());
    bool valid = hmac->verify_mac(mac.data(), mac.size());
    
    return valid ? 0 : 1;
}
