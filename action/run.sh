#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
    echo "WuppieFuzz Action: $*" >&2
    exit 1
}

[[ "${RUNNER_OS:-}" == "Linux" ]] || fail "only Linux runners are supported"
command -v curl >/dev/null || fail "curl is required"
command -v docker >/dev/null || fail "Docker is required"
command -v sha256sum >/dev/null || fail "sha256sum is required"

[[ -n "${INPUT_OPENAPI_SPEC:-}" ]] || fail "openapi-spec is required"
[[ -n "${INPUT_DOCKER_IMAGE:-}" ]] || fail "docker-image is required"
[[ "${INPUT_TIMEOUT:-}" =~ ^[1-9][0-9]*$ ]] || fail "timeout must be a positive integer"
[[ "${INPUT_STARTUP_WAIT:-}" =~ ^[0-9]+$ ]] || fail "startup-wait must be a non-negative integer"

if [[ "$INPUT_OPENAPI_SPEC" = /* ]]; then
    spec_path="$INPUT_OPENAPI_SPEC"
else
    spec_path="${GITHUB_WORKSPACE:?}/${INPUT_OPENAPI_SPEC}"
fi
[[ -f "$spec_path" ]] || fail "OpenAPI specification not found: $spec_path"
spec_path="$(realpath "$spec_path")"

version="${INPUT_WUPPIEFUZZ_VERSION#v}"
if [[ -z "$version" ]]; then
    version="$(awk -F '"' '/^version = "/ { print $2; exit }' "${GITHUB_ACTION_PATH:?}/Cargo.toml")"
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$ ]] \
    || fail "invalid WuppieFuzz version: $version"

case "$(uname -m)" in
    x86_64 | amd64) target="x86_64-unknown-linux-gnu" ;;
    aarch64 | arm64) target="aarch64-unknown-linux-gnu" ;;
    *) fail "unsupported runner architecture: $(uname -m)" ;;
esac

run_key="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-${BASHPID}"
work_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/wuppiefuzz-action.XXXXXX")"
results_dir="${RUNNER_TEMP:-/tmp}/wuppiefuzz-results-${run_key}"
run_dir="${work_dir}/run"
install_dir="${work_dir}/install"
container_id=""
mkdir -p "$results_dir" "$run_dir" "$install_dir"
touch "$results_dir/target-container.log"
echo "results-path=$results_dir" >> "${GITHUB_OUTPUT:?}"

cleanup() {
    status=$?
    trap - EXIT
    set +e

    if [[ -n "$container_id" ]] && docker inspect "$container_id" >/dev/null 2>&1; then
        # ponytail: keep CI artifacts bounded; make this configurable if full logs are needed.
        docker logs --tail 1000 "$container_id" > "$results_dir/target-container.log" 2>&1
        docker rm --force "$container_id" >/dev/null
    fi
    for directory in reports crashes; do
        if [[ -e "$run_dir/$directory" ]]; then
            cp -a "$run_dir/$directory" "$results_dir/" || status=1
        fi
    done

    exit "$status"
}
trap cleanup EXIT

archive="wuppiefuzz-${target}.tar.xz"
release_url="https://github.com/TNO-S3/WuppieFuzz/releases/download/v${version}"
curl --fail --location --retry 3 --show-error --silent \
    --output "$install_dir/$archive" "$release_url/$archive"
curl --fail --location --retry 3 --show-error --silent \
    --output "$install_dir/$archive.sha256" "$release_url/$archive.sha256"
(
    cd "$install_dir"
    sha256sum --check "$archive.sha256"
)
tar --extract --xz --file "$install_dir/$archive" --directory "$install_dir" \
    --strip-components 1
wuppiefuzz="$install_dir/wuppiefuzz"
[[ -x "$wuppiefuzz" ]] || fail "release archive did not contain the WuppieFuzz executable"

docker pull "$INPUT_DOCKER_IMAGE"
container_id="$(docker run --detach --network host "$INPUT_DOCKER_IMAGE")"

elapsed=0
while ((elapsed < INPUT_STARTUP_WAIT)); do
    [[ "$(docker inspect --format '{{.State.Running}}' "$container_id")" == "true" ]] \
        || fail "target container stopped during startup"
    health="$(docker inspect \
        --format '{{if .Config.Healthcheck}}{{.State.Health.Status}}{{else}}none{{end}}' \
        "$container_id")"
    case "$health" in
        healthy) break ;;
        unhealthy) fail "target container reported an unhealthy status" ;;
    esac
    sleep 1
    elapsed=$((elapsed + 1))
done

[[ "$(docker inspect --format '{{.State.Running}}' "$container_id")" == "true" ]] \
    || fail "target container is not running"
health="$(docker inspect \
    --format '{{if .Config.Healthcheck}}{{.State.Health.Status}}{{else}}none{{end}}' \
    "$container_id")"
[[ "$health" != "starting" ]] \
    || fail "target container did not become healthy within ${INPUT_STARTUP_WAIT} seconds"

cd "$run_dir"
"$wuppiefuzz" fuzz --log-level warn --report --timeout "$INPUT_TIMEOUT" "$spec_path"
