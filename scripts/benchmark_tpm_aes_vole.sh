#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"
source_dir="${project_dir}/vendor/TPM_AES"
build_dir="${TPM_AES_BUILD_DIR:-${HOME}/.cache/sedaa-tpm-aes-vole}"
iterations="${ITERATIONS:-20}"
phases="${PHASES:-join,sign}"
parameters="${PARAMETERS:-128s,128f,192s,192f,256s,256f}"
timestamp="$(date +%Y%m%d-%H%M%S)"
log_dir="${TPM_AES_LOG_DIR:-${project_dir}/benchmarks/tpm_aes}"
log_file="${TPM_AES_LOG:-${log_dir}/tpm_aes_${timestamp}.log}"

phases="${phases// /,}"
parameters="${parameters// /,}"

if [[ ! "${iterations}" =~ ^[1-9][0-9]*$ ]]; then
  printf 'ITERATIONS must be a positive integer\n' >&2
  exit 2
fi
for phase in ${phases//,/ }; do
  if [[ "${phase}" != "join" && "${phase}" != "sign" ]]; then
    printf 'PHASES accepts only join and sign, got: %s\n' "${phase}" >&2
    exit 2
  fi
done
for parameter in ${parameters//,/ }; do
  case "${parameter}" in
    128s|128f|192s|192f|256s|256f) ;;
    *) printf 'unsupported PARAMETERS entry: %s\n' "${parameter}" >&2; exit 2 ;;
  esac
done

if [[ "${DRY_RUN:-0}" == 1 ]]; then
  PARAMS_LIST="$parameters" python3 "$script_dir/benchmark.py" tpm --tpm-backend aes --list
  exit
fi

mkdir -p "${build_dir}" "${log_dir}"
if [[ -f "${build_dir}/build.ninja" ]]; then
  meson setup --reconfigure "${build_dir}" "${source_dir}" --buildtype=release
else
  meson setup "${build_dir}" "${source_dir}" --buildtype=release
fi
meson compile -C "${build_dir}" daa_aes_profile

raw_output="$(PARAMETERS="$parameters" PHASES="$phases" "${build_dir}/daa_aes_profile" "${iterations}")"
{
  printf 'AES VOLE DAA benchmark: AES-128-DM; AES-192 and AES-256\n'
  printf 'date=%s\n' "$(date --iso-8601=seconds)"
  printf 'iterations=%s\n' "${iterations}"
  printf 'phases=%s\n' "${phases}"
  printf 'parameters=%s\n' "${parameters}"
  printf 'build_dir=%s\n\n' "${build_dir}"
  printf '%s\n' "${raw_output}" | awk -F '\t' \
    -v selected_phases=",${phases}," \
    -v selected_parameters=",${parameters}," \
    'NR == 1 || (index(selected_phases, "," $1 ",") &&
                 index(selected_parameters, "," $2 ","))'
} | tee "${log_file}"

printf '\nSaved benchmark log: %s\n' "${log_file}"
