-module(main).
-export([main/0]).

main() ->
    Message = <<"Hello, World!">>,
    Hash = crypto:hash(sha256, Message),
    ok.
