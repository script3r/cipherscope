#include <botan/hash.h>
#include <string>
#include <vector>

int main() {
    std::string message = "Hello, World!";
    
    auto hash = Botan::HashFunction::create("SHA-256");
    hash->update((const uint8_t*)message.data(), message.size());
    std::vector<uint8_t> digest = hash->final();
    
    return 0;
}
