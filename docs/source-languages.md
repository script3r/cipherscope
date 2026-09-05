# Source language selection

Directory discovery and explicit source paths use the same extension resolver.
Extensions are case-insensitive, with one conventional exception: `.c` selects C
and `.C` selects C++. A file is scanned only if its parser feature is enabled and
the pattern set contains definitions for its language.

`.ts`, `.mts`, and `.cts` use the TypeScript grammar. `.tsx` uses the dedicated
TSX grammar, represented by `Language::Tsx` in the library API. Both use
`lang-typescript` and the `TypeScript` pattern definitions. Ordinary TypeScript
continues to accept angle-bracket type assertions, which conflict with JSX syntax.

Ambiguous `.h` files prefer C++ when available and fall back to C in C-only builds.
The OpenSSL C fixture family runs whenever `lang-c` is enabled; it does not require
the C++ parser.
