-module(main).
-export([main/0]).

main() ->
    Key = <<"secret_key">>,
    Message = <<"Hello, World!">>,
    
    % Create HMAC
    Mac = crypto:mac(hmac, sha256, Key, Message),
    
    % Verify HMAC (compare with expected)
    ExpectedMac = crypto:mac(hmac, sha256, Key, Message),
    Mac = ExpectedMac,
    ok.
