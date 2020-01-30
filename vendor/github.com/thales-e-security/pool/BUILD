load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "go_default_library",
    srcs = [
        "atomic.go",
        "resource_pool.go",
        "semaphore.go",
        "timer.go",
    ],
    importmap = "k8s.io/kubernetes/vendor/github.com/thales-e-security/pool",
    importpath = "github.com/thales-e-security/pool",
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
