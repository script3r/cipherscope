java_binary(
    name = "crypto_example",
    srcs = ["src/main/java/com/example/CryptoExample.java"],
    main_class = "com.example.CryptoExample",
    deps = [
        "@bouncycastle_bcprov//jar",
        "@bouncycastle_bcpkix//jar",
        "@tink//jar",
    ],
)

java_test(
    name = "crypto_test",
    srcs = ["src/test/java/com/example/CryptoTest.java"],
    deps = [
        ":crypto_example",
        "@bouncycastle_bcprov//jar",
    ],
)