#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"
source_dir="${project_dir}/vendor/TPM_SHA"
build_dir="${TPM_SHA_BUILD_DIR:-${project_dir}/target/native-tpm-sha}"

security="${SECURITY:-all}"
profile="${PROFILE:-all}"
scheme="${SCHEME:-all}"
iterations="${ITERATIONS:-10}"

if [[ ! "$iterations" =~ ^[1-9][0-9]*$ ]]; then
  echo "ITERATIONS must be a positive integer" >&2; exit 2
fi
case "$security" in all|128|192|256) ;; *) echo "invalid SECURITY" >&2; exit 2 ;; esac
case "$profile" in all|s|f) ;; *) echo "invalid PROFILE" >&2; exit 2 ;; esac
case "$scheme" in all|ours|chen23) ;; *) echo "invalid SCHEME" >&2; exit 2 ;; esac
params_list="${PARAMS_LIST:-}"
params_list="${params_list//,/ }"
selected_params=()
for parameter in $params_list; do
  parameter="${parameter#sha2-}"
  case "$parameter" in 128s|128f|192s|192f|256s|256f) ;; *) echo "invalid PARAMS_LIST" >&2; exit 2 ;; esac
  if [[ "$security" != all && "${parameter%[sf]}" != "$security" ]]; then continue; fi
  if [[ "$profile" != all && "${parameter: -1}" != "$profile" ]]; then continue; fi
  if [[ " ${selected_params[*]} " != *" $parameter "* ]]; then selected_params+=("$parameter"); fi
done
if [[ -n "$params_list" && ${#selected_params[@]} == 0 ]]; then
  echo "no supported parameters selected" >&2; exit 2
fi
if [[ "${DRY_RUN:-0}" == 1 ]]; then
  if [[ -z "$params_list" ]]; then
    for parameter in 128s 128f 192s 192f 256s 256f; do
      if [[ "$security" != all && "${parameter%[sf]}" != "$security" ]]; then continue; fi
      if [[ "$profile" != all && "${parameter: -1}" != "$profile" ]]; then continue; fi
      selected_params+=("$parameter")
    done
  fi
  PARAMS_LIST="${selected_params[*]}" python3 "$script_dir/benchmark.py" tpm --tpm-backend sha2 --list
  exit
fi
if [[ -f "${build_dir}/build.ninja" ]]; then
  meson setup --reconfigure "${build_dir}" "${source_dir}" --buildtype=release
else
  meson setup "${build_dir}" "${source_dir}" --buildtype=release
fi
meson compile -C "${build_dir}" tpm_sha_benchmark

args=(--scheme "${scheme}" --profile "${profile}" --iterations "${iterations}")
if [[ "${security}" != "all" ]]; then
  args+=(--security "${security}")
fi
if [[ -n "$params_list" && "${selected_params[*]}" != "128s 128f 192s 192f 256s 256f" ]]; then
  for parameter in "${selected_params[@]}"; do
    "${build_dir}/tpm_sha_benchmark" --scheme "$scheme" --security "${parameter%[sf]}" \
      --profile "${parameter: -1}" --iterations "$iterations"
  done
else
  "${build_dir}/tpm_sha_benchmark" "${args[@]}"
fi
