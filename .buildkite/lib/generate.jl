import YAML

include(joinpath(@__DIR__, "common.jl"))

function generate(platform::Platform)
    commands = """
    echo "--- Print kernel information"
    uname -a

    echo "--- Print CPU information"
    # These machines have multiple cores. However, it should be sufficient to
    # just print the information for one of the cores.
    sed -n '1,/^\$\$/p' /proc/cpuinfo

    if [[ "$(platform.arch)" == "aarch64" ]]; then
      echo "--- Patch glibc host environment"
      curl -LO https://github.com/JuliaBinaryWrappers/DebianGlibc_jll.jl/releases/download/DebianGlibc-v2.33.0%2B1/DebianGlibc.v2.33.0.aarch64-linux-gnu.tar.gz
      tar -C / -xf DebianGlibc.v2.33.0.aarch64-linux-gnu.tar.gz
    fi

    echo "--- Generate build environment"
    cmake --version
    rm -rf obj
    mkdir obj
    cd obj
    cmake ..

    echo "--- Build"
    make --output-sync -j\$\${JULIA_CPU_THREADS:?}
    bin/rr --log all:info bin/simple

    echo "--- Test"
    mkdir -p Testing/Temporary
    mv ../.buildkite/CTestCostData.txt Testing/Temporary
    if bin/rr record bin/simple; then
      julia ../.buildkite/capture_tmpdir.jl ctest --output-on-failure -j\$\$(expr \$\${JULIA_CPU_THREADS:?} - 2)
    else
      echo -n -e "rr seems not able to run, skipping running test suite.\nhostname: "
      hostname
      exit 1
    fi
    """
    job_label = "Test $(platform.arch)"
    job_key = "test-$(platform.arch)"
    yaml = Dict(
        "steps" => [
            Dict(
                "label" => job_label,
                "key" => job_key,
                "timeout_in_minutes" => 45,
                "agents" => Dict(
                    "sandbox_capable" => "true",
                    "queue" => "juliaecosystem",
                    "arch" => "$(platform.arch)",
                    "os" => "linux",
                ),
                "commands" => commands,
                "plugins" => [
                    Dict(
                        "JuliaCI/julia#v1" => Dict(
                            "persist_depot_dirs" => "packages,artifacts,compiled",
                            "version" => "1.7",
                        ),
                    ),
                    Dict(
                        "staticfloat/sandbox#v1" => Dict(
                            "rootfs_treehash" => "$(platform.rootfs_treehash)",
                            "verbose" => true,
                            "rootfs_url" => "https://github.com/JuliaCI/rootfs-images/releases/download/$(platform.rootfs_tag)/rr.$(platform.arch).tar.gz",
                            "workspaces" => ["/cache:/cache"],
                        ),
                    ),
                ],
                "soft_fail" => "$(platform.allow_fail)",
                "retry" => Dict("manual" => Dict("permit_on_passed" => true))
            ),
        ],
    )
    if platform.commit_status
        let
            notify = [
                Dict(
                    "github_commit_status" => Dict(
                        "context" => job_key,
                    ),
                ),
            ]
            only(yaml["steps"])["notify"] = notify
        end
    end
    yaml_path = get_yaml_path(platform)
    rm(yaml_path; force = true)
    YAML.write_file(yaml_path, yaml)
end

generate.(platforms)
