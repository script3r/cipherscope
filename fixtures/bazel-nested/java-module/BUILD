java_library(
    name = "crypto_lib",
    srcs = ["JavaCrypto.java"],
    deps = [
        "@bouncycastle//jar",
    ],
    visibility = ["//visibility:public"],
)

java_binary(
    name = "crypto_demo",
    srcs = ["JavaCrypto.java"],
    main_class = "JavaCrypto",
    deps = [":crypto_lib"],
)