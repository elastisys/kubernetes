load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "const.go",
        "error.go",
        "params.go",
        "pkcs11.go",
        "pkcs11.h",
        "pkcs11f.h",
        "pkcs11go.h",
        "pkcs11t.h",
        "types.go",
        "vendor.go",
    ],
    cgo = True,
    clinkopts = select({
        "@io_bazel_rules_go//go/platform:android": [
            "-ldl",
        ],
        "@io_bazel_rules_go//go/platform:darwin": [
            "-ldl",
        ],
        "@io_bazel_rules_go//go/platform:freebsd": [
            "-ldl",
        ],
        "@io_bazel_rules_go//go/platform:ios": [
            "-ldl",
        ],
        "@io_bazel_rules_go//go/platform:linux": [
            "-ldl",
        ],
        "@io_bazel_rules_go//go/platform:openbsd": [
            "-ldl",
        ],
        "//conditions:default": [],
    }),
    copts = select({
        "@io_bazel_rules_go//go/platform:windows": [
            "-DPACKED_STRUCTURES",
        ],
        "//conditions:default": [],
    }),
    importmap = "k8s.io/kubernetes/vendor/github.com/miekg/pkcs11",
    importpath = "github.com/miekg/pkcs11",
    visibility = ["//visibility:public"],
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
