#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/keyset_handle.h"
#include "tink/config/tink_config.h"

#include <iostream>
#include <memory>
#include <string>

using crypto::tink::Aead;
using crypto::tink::AeadKeyTemplates;
using crypto::tink::KeysetHandle;
using crypto::tink::TinkConfig;

int main() {
    // Initialize Tink
    auto status = TinkConfig::Register();
    if (!status.ok()) {
        std::cerr << "Tink config registration failed" << std::endl;
        return 1;
    }

    // Generate new keyset with AES256-GCM
    auto keyset_handle_result = KeysetHandle::GenerateNew(
        AeadKeyTemplates::Aes256Gcm());
    if (!keyset_handle_result.ok()) {
        std::cerr << "Key generation failed" << std::endl;
        return 1;
    }
    auto keyset_handle = std::move(keyset_handle_result.value());

    // Get the AEAD primitive
    auto aead_result = keyset_handle->GetPrimitive<Aead>();
    if (!aead_result.ok()) {
        std::cerr << "Getting primitive failed" << std::endl;
        return 1;
    }
    auto aead = std::move(aead_result.value());

    // Encrypt
    std::string plaintext = "Hello Tink C++";
    std::string associated_data = "metadata";
    auto encrypt_result = aead->Encrypt(plaintext, associated_data);
    if (!encrypt_result.ok()) {
        std::cerr << "Encryption failed" << std::endl;
        return 1;
    }
    std::string ciphertext = encrypt_result.value();

    // Decrypt
    auto decrypt_result = aead->Decrypt(ciphertext, associated_data);
    if (!decrypt_result.ok()) {
        std::cerr << "Decryption failed" << std::endl;
        return 1;
    }
    std::cout << "Decrypted: " << decrypt_result.value() << std::endl;

    return 0;
}
