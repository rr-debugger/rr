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
            rootfs_tag      = "v5.14",
            rootfs_treehash = "72dab0734a234d2277e3a204263ec7d038b4087e",
            allow_fail      = false,
            commit_status   = true,
        ),
        Platform(;
            arch            = "aarch64",
            rootfs_tag      = "v5.14",
            rootfs_treehash = "20db175a1cc643f6d05f172eae921171e95326d3",
            allow_fail      = true,
            commit_status   = false,
        ),
    ]
)
