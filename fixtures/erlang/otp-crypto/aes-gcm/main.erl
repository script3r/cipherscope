-module(main).
-export([main/0]).

main() ->
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),
    Plaintext = <<"Hello, World!">>,
    
    % Encrypt
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Plaintext, <<>>, true),
    
    % Decrypt
    Decrypted = crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Ciphertext, <<>>, Tag, false),
    ok.
