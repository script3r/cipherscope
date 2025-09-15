py_library(
    name = "crypto_lib",
    srcs = ["crypto_utils.py"],
    deps = [
        "@pip_deps//cryptography",
        "@pip_deps//pycryptodome",
    ],
    visibility = ["//visibility:public"],
)

py_binary(
    name = "crypto_demo",
    srcs = ["crypto_utils.py"],
    deps = [":crypto_lib"],
)