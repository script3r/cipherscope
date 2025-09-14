-module(main).
-export([main/0]).

-include_lib("public_key/include/public_key.hrl").

main() ->
    % Test Erlang/OTP crypto module
    Key = crypto:generate_key(des3, 24),
    Hash = crypto:hash(sha256, "hello world"),
    Cipher = crypto:block_encrypt(aes_256_cbc, Key, "plaintext"),
    
    % Test public_key module
    {ok, Pem} = public_key:pem_decode(<<"-----BEGIN PRIVATE KEY-----">>),
    Signature = public_key:sign("data", sha256, Pem),
    
    % Test enacl (libsodium) if available
    {PublicKey, SecretKey} = enacl:box_keypair(),
    Nonce = enacl:randombytes(12),
    Ciphertext = enacl:box("message", Nonce, PublicKey, SecretKey),
    
    % Test bcrypt
    Hash2 = bcrypt:hashpw("password", bcrypt:gen_salt()),
    
    io:format("Crypto operations completed~n").
