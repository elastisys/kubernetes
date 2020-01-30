load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "aead.go",
        "attributes.go",
        "block.go",
        "blockmode.go",
        "certificates.go",
        "common.go",
        "crypto11.go",
        "dsa.go",
        "ecdsa.go",
        "hmac.go",
        "keys.go",
        "rand.go",
        "rsa.go",
        "sessions.go",
        "symmetric.go",
    ],
    cgo = True,
    importmap = "k8s.io/kubernetes/vendor/github.com/ThalesIgnite/crypto11",
    importpath = "github.com/ThalesIgnite/crypto11",
    visibility = ["//visibility:public"],
    deps = [
        "//vendor/github.com/miekg/pkcs11:go_default_library",
        "//vendor/github.com/pkg/errors:go_default_library",
        "//vendor/github.com/thales-e-security/pool:go_default_library",
    ],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
    visibility = ["//visibility:public"],
)
