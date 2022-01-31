import Dates
import Pkg
import Tar

function my_exit(process::Base.Process)
    wait(process)

    @info(
        "",
        process.exitcode,
        process.termsignal,
    )

    # Pass the exit code back up
    if process.termsignal != 0
        ccall(:raise, Cvoid, (Cint,), process.termsignal)

        # If for some reason the signal did not cause an exit, we'll exit manually.
        # We need to make sure that we exit with a non-zero exit code.
        if process.exitcode != 0
            exit(process.exitcode)
        else
            exit(1)
        end
    end
    exit(process.exitcode)
end

function get_bool_from_env(name::AbstractString, default_value::Bool)
    value = get(ENV, name, "$(default_value)") |> strip |> lowercase
    result = parse(Bool, value)::Bool
    return result
end

const is_buildkite = get_bool_from_env("BUILDKITE", false)

function get_from_env(name::AbstractString)
    if is_buildkite
        value = ENV[name]
    else
        value = get(ENV, name, "")
    end
    result = convert(String, strip(value))::String
    return result
end

cleanup_string(str::AbstractString) = replace(str, r"[^A-Za-z0-9_]" => "_")

if Base.VERSION < v"1.6"
    throw(ErrorException("The `$(basename(@__FILE__))` script requires Julia 1.6 or greater"))
end

if length(ARGS) < 1
    throw(ErrorException("Usage: julia $(basename(@__FILE__)) [command...]"))
end

const build_number    = get_from_env("BUILDKITE_BUILD_NUMBER") |> cleanup_string
const job_name        = get_from_env("BUILDKITE_STEP_KEY")     |> cleanup_string
const commit_full     = get_from_env("BUILDKITE_COMMIT")       |> cleanup_string
const commit_short    = first(commit_full, 10)
const timeout_minutes = 30
const cleanup_minutes = 10

@info(
    "",
    build_number,
    job_name,
    commit_full,
    commit_short,
    timeout_minutes,
    cleanup_minutes,
)

const my_archives_dir    = joinpath(pwd(), "my_archives_dir")
const my_temp_parent_dir = joinpath(pwd(), "my_temp_parent_dir")

mkpath(my_archives_dir)
mkpath(my_temp_parent_dir)

const TMPDIR = mktempdir(my_temp_parent_dir)

proc = nothing

mktempdir(my_temp_parent_dir) do dir
    Pkg.activate(dir)
    Pkg.add("Zstd_jll")
    zstd_jll = Base.require(Base.PkgId(Base.UUID("3161d3a3-bdf6-5164-811a-617609db77b4"), "Zstd_jll"))
    # zstdmt(func) = Base.invokelatest(zstd_jll.zstdmt, func; adjust_LIBPATH=false)
    zstdmt(func) = Base.invokelatest(zstd_jll.zstdmt, func)

    new_env = copy(ENV)
    new_env["TMPDIR"] = TMPDIR
    command = setenv(`$ARGS`, new_env)
    global proc = run(command, (stdin, stdout, stderr); wait = false)

    # Start asynchronous timer that will kill the process.
    @async begin
        sleep(timeout_minutes * 60)

        # If we've exceeded the timeout and the process is still running, kill it with `SIGTERM`.
        if isopen(proc)
            println(stderr, "\n\nProcess timed out (with a timeout of $(timeout_minutes) minutes). Signalling for force-cleanup!")
            kill(proc, Base.SIGTERM)

            # Give the process a chance to cleanup and upload.
            # Note: this time period includes the time to upload the `rr` trace files
            # as Buildkite artifacts, so make sure it is long enough to allow the
            # uploads to finish.
            sleep(cleanup_minutes * 60)

            if isopen(proc)
                println(stderr, "\n\nProcess failed to cleanup and upload within $(cleanup_minutes) minutes, killing and exiting immediately!")
                kill(proc, Base.SIGKILL)

                # make sure to exit with a non-zero exit code
                exit(1)
            end
        end
    end

    # Wait for the process to finish, either through naturally finishing its run, or `SIGTERM`.
    wait(proc)

    if proc.termsignal != 0
        @info "Command signalled $(proc.termsignal)"
    else
        @info "Command returned $(proc.exitcode)"
    end
    date_str = Dates.format(Dates.now(), Dates.dateformat"yyyy_mm_dd_HH_MM_SS")
    artifact_specifications = [
        ("TMPDIR", TMPDIR),
    ]
    for (artifact_name, artifact_input_dir) in artifact_specifications
        dst_file_name = string(
            artifact_name,
            "--build_$(build_number)",
            "--$(job_name)",
            "--commit_$(commit_short)",
            "--$(date_str)",
            ".tar.zst",
        )
        dst_full_path = joinpath(my_archives_dir, dst_file_name)
        zstdmt() do zstdp
            tarproc = open(`$(zstdp) -o $(dst_full_path)`, "w")
            Tar.create(artifact_input_dir, tarproc)
            close(tarproc.in)
        end

        buildkite_upload_cmd = `buildkite-agent artifact upload $(dst_file_name)`
        if is_buildkite && !success(proc)
            run(setenv(buildkite_upload_cmd; dir = my_archives_dir))
        end
    end
end

my_exit(proc)
