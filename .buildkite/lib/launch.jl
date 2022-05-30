include(joinpath(@__DIR__, "common.jl"))

function launch(platform::Platform)
    yaml_path = get_yaml_path(platform)
    cmd = `buildkite-agent pipeline upload $(yaml_path)`
    run(cmd)
    return nothing
end

launch.(platforms)
