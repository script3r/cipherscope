-module(app).
-export([main/0]).

main() ->
    crypto:hash(sha256, <<"hi">>).
