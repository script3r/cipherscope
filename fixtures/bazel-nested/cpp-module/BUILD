cc_library(
    name = "crypto_lib",
    srcs = ["crypto.cpp"],
    hdrs = ["crypto.h"],
    deps = [
        "@openssl//:ssl",
        "@openssl//:crypto",
    ],
    visibility = ["//visibility:public"],
)

cc_binary(
    name = "crypto_demo",
    srcs = ["main.cpp"],
    deps = [":crypto_lib"],
)