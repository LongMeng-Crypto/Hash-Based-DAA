#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"
source_dir="${project_dir}/vendor/TPM_SHA"
build_dir="${TPM_SHA_BUILD_DIR:-${HOME}/.cache/sedaa-tpm-sha-relations}"

security="${SECURITY:-all}"
profile="${PROFILE:-all}"
scheme="${SCHEME:-all}"
iterations="${ITERATIONS:-10}"

if [[ -f "${build_dir}/build.ninja" ]]; then
  meson setup --reconfigure "${build_dir}" "${source_dir}" --buildtype=release
else
  meson setup "${build_dir}" "${source_dir}" --buildtype=release
fi
meson compile -C "${build_dir}"

args=(--scheme "${scheme}" --profile "${profile}" --iterations "${iterations}")
if [[ "${security}" != "all" ]]; then
  args+=(--security "${security}")
fi
"${build_dir}/tpm_sha_benchmark" "${args[@]}"
