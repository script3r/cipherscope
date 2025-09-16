-module(main).
-export([main/0]).

main() ->
    Message = <<"Hello, World!">>,
    
    % Generate RSA key pair
    {PublicKey, PrivateKey} = crypto:generate_key(rsa, {2048, 65537}),
    
    % Sign
    Signature = crypto:sign(rsa, sha256, Message, PrivateKey),
    
    % Verify
    true = crypto:verify(rsa, sha256, Message, Signature, PublicKey),
    ok.
