Base.@kwdef struct Platform
    arch::String
    rootfs_tag::String
    rootfs_treehash::String
    allow_fail::Bool
    commit_status::Bool
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
            rootfs_tag      = "v7.0",
            rootfs_treehash = "ee8a34cb17337e367e8c40b1df2c481a2ec78c56",
            allow_fail      = false,
            commit_status   = true,
        ),
        Platform(;
            arch            = "aarch64",
            rootfs_tag      = "v7.0",
            rootfs_treehash = "a046a7a1e5498c2bf51829926513220d0de13b02",
            allow_fail      = false,
            commit_status   = true,
        ),
    ]
)
