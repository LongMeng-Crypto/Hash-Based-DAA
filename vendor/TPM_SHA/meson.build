project(
  'DAA-TPM-SHA',
  ['c', 'cpp'],
  version: '0.1.0',
  meson_version: '>=0.59',
  default_options: ['cpp_std=c++20', 'warning_level=3'],
)

openssl = dependency('openssl')
root = meson.current_source_dir()
prefix_header = join_paths(root, 'include', 'tpm_sha_faest_prefix.h')
prefix_args = ['-include', prefix_header, '-fvisibility=hidden']
faest_includes = include_directories(
  'third_party/faest',
  'third_party/faest/sha3',
  'third_party/faest/sha3/opt64',
)
project_includes = include_directories(
  '.', 'include', 'backend', 'backend/vole', 'circuits/sha256'
)

faest_sources = files(
  'third_party/faest/aes.c',
  'third_party/faest/bavc.c',
  'third_party/faest/compat.c',
  'third_party/faest/fields.c',
  'third_party/faest/faest_aes_128.c',
  'third_party/faest/instances.c',
  'third_party/faest/random_oracle.c',
  'third_party/faest/universal_hashing.c',
  'third_party/faest/utils.c',
  'third_party/faest/vole.c',
  'third_party/faest/sha3/KeccakHash.c',
  'third_party/faest/sha3/KeccakSponge.c',
  'third_party/faest/sha3/opt64/KeccakP-1600-opt64.c',
)

backend_sources = files(
  'backend/binary_circuit.cpp',
  'backend/backend_witness.cpp',
  'backend/prepared_binary_circuit.cpp',
  'backend/circuit_format.cpp',
  'backend/security_parameters.cpp',
  'backend/quadratic_relation.cpp',
  'backend/vole/gf128.cpp',
  'backend/vole/bit_matrix_transpose.cpp',
  'backend/generic_quicksilver.cpp',
  'backend/generic_nizk.cpp',
  'backend/vole/faest_vole.cpp',
  'backend/vole/quicksilver.cpp',
)

frontend_sources = files(
  'circuits/common/input_visibility.cpp',
  'circuits/sha256/sha256_core.cpp',
  'circuits/sha2/sha512_family.cpp',
  'src/tpm_sha_relation.cpp',
  'src/tpm_sha.cpp',
  'src/issuer_anchor_relation.cpp',
  'src/issuer_anchor_nizk.cpp',
)

faest_internal = static_library(
  'daa_tpm_sha_faest', faest_sources,
  include_directories: faest_includes,
  dependencies: openssl,
  c_args: prefix_args + ['-DFAEST_STATIC', '-DFAEST_EXPORT=', '-DFAEST_TESTS'],
)

tpm_sha_lib = static_library(
  'daa_tpm_sha', backend_sources + frontend_sources,
  include_directories: [project_includes, faest_includes],
  link_with: faest_internal,
  dependencies: openssl,
  cpp_args: prefix_args,
)

tpm_sha_dep = declare_dependency(
  link_with: [tpm_sha_lib, faest_internal],
  include_directories: [project_includes, faest_includes],
  dependencies: openssl,
)

tpm_sha_tests = executable(
  'tpm_sha_tests', files('tests/tpm_sha_tests.cpp'),
  dependencies: [tpm_sha_dep, openssl],
  cpp_args: prefix_args + ['-DFAEST_TESTS'],
)

tpm_sha_benchmark = executable(
  'tpm_sha_benchmark', files('src/tpm_sha_benchmark.cpp'),
  dependencies: [tpm_sha_dep],
  cpp_args: prefix_args,
)

test('DAA TPM SHA', tpm_sha_tests, timeout: 180)
