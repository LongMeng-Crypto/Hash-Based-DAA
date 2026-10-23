#!/usr/bin/env bash
set -euo pipefail

# Benchmark the independent Rijndael-256 DM line without altering AES/SHA results.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd -- "${script_dir}/.." && pwd)"
source_dir="${project_dir}/vendor/TPM_AES"
build_dir="${TPM_RDM_BUILD_DIR:-${HOME}/.cache/sedaa-tpm-rdm-vole}"
iterations="${ITERATIONS:-20}"
phases="${PHASES:-join,sign}"
parameters="${PARAMETERS:-128s,128f}"
timestamp="$(date +%Y%m%d-%H%M%S)"
log_dir="${TPM_RDM_LOG_DIR:-${project_dir}/benchmarks/tpm_rijndael_dm}"
log_file="${TPM_RDM_LOG:-${log_dir}/tpm_rijndael_dm_${timestamp}.log}"

phases="${phases// /,}"
parameters="${parameters// /,}"
if [[ ! "${iterations}" =~ ^[1-9][0-9]*$ ]]; then
  printf 'ITERATIONS must be a positive integer\n' >&2
  exit 2
fi
for phase in ${phases//,/ }; do
  [[ "${phase}" == join || "${phase}" == sign ]] || {
    printf 'PHASES accepts only join and sign, got: %s\n' "${phase}" >&2
    exit 2
  }
done
for parameter in ${parameters//,/ }; do
  [[ "${parameter}" == 128s || "${parameter}" == 128f ]] || {
    printf 'PARAMETERS accepts only 128s and 128f, got: %s\n' "${parameter}" >&2
    exit 2
  }
done

mkdir -p "${build_dir}" "${log_dir}"
if [[ -f "${build_dir}/build.ninja" ]]; then
  meson setup --reconfigure "${build_dir}" "${source_dir}" --buildtype=release
else
  meson setup "${build_dir}" "${source_dir}" --buildtype=release
fi
meson compile -C "${build_dir}" daa_rijndael_dm_profile

raw_output="$("${build_dir}/daa_rijndael_dm_profile" "${iterations}")"
{
  printf 'Rijndael-256 Davies--Meyer VOLE DAA benchmark\n'
  printf 'construction=F(K,D)=Rijndael256_K(D) xor D (256-bit output, no truncation)\n'
  printf 'vole_security=128\n'
  printf 'date=%s\n' "$(date --iso-8601=seconds)"
  printf 'commit=%s\n' "$(git -C "${project_dir}" rev-parse --short HEAD 2>/dev/null || printf unknown)"
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
