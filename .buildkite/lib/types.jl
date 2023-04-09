Base.@kwdef struct Platform
    arch::String
    rootfs_tag::String
    rootfs_treehash::String
    allow_fail::Bool
    commit_status::Bool
    cmake_extra_arg::String
    variant::String
end

struct Platforms
    ps::Vector{Platform}
end

Base.length(platforms::Platforms)         = Base.length(platforms.ps)
Base.iterate(platforms::Platforms)        = Base.iterate(platforms.ps)
Base.iterate(platforms::Platforms, state) = Base.iterate(platforms.ps, state)

const platforms = Platforms(
    [
        Platform(;
            arch            = "x86_64",
            rootfs_tag      = "v5.22",
            rootfs_treehash = "1cd67e278881dcfeed695282256b26fad603e15d",
            allow_fail      = false,
            commit_status   = true,
            cmake_extra_arg = "",
            variant         = "",
        ),
        Platform(;
            arch            = "x86_64",
            rootfs_tag      = "v5.22",
            rootfs_treehash = "1cd67e278881dcfeed695282256b26fad603e15d",
            allow_fail      = false,
            commit_status   = true,
            cmake_extra_arg = "-Dasan=true",
            variant         = "asan",
        ),
        Platform(;
            arch            = "aarch64",
            rootfs_tag      = "v5.22",
            rootfs_treehash = "7a63218e46996b36aa108b55746a3d94a3e312c1",
            allow_fail      = false,
            commit_status   = true,
            cmake_extra_arg = "",
            variant         = "",
        ),
        Platform(;
            arch            = "aarch64",
            rootfs_tag      = "v5.22",
            rootfs_treehash = "7a63218e46996b36aa108b55746a3d94a3e312c1",
            allow_fail      = false,
            commit_status   = true,
            cmake_extra_arg = "-Dasan=true",
            variant         = "asan",
        ),
        Platform(;
            arch            = "x86_64",
            rootfs_tag      = "v5.22",
            rootfs_treehash = "1cd67e278881dcfeed695282256b26fad603e15d",
            allow_fail      = false,
            commit_status   = true,
            cmake_extra_arg = "-Dforce32bit=true",
            variant         = "force32bit",
        ),
        Platform(;
            arch            = "x86_64",
            rootfs_tag      = "v5.22",
            rootfs_treehash = "1cd67e278881dcfeed695282256b26fad603e15d",
            allow_fail      = false,
            commit_status   = true,
            cmake_extra_arg = "-Dforce32bit=true -Dasan=true",
            variant         = "force32bit-asan",
        ),
    ]
)
