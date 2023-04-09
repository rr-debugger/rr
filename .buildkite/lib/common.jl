include(joinpath(@__DIR__, "types.jl"))

function get_yaml_path(platform::Platform)
    lib_dir = @__DIR__
    buildkite_dir = dirname(lib_dir)
    yaml_path = joinpath(buildkite_dir, "test-$(platform.arch).yml")
    if platform.variant != ""
        yaml_path = joinpath(buildkite_dir, "test-$(platform.arch)-$(platform.variant).yml")
    end
    return yaml_path
end
