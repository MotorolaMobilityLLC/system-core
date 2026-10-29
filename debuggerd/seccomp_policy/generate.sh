#!/bin/bash

set -e

cd "$(dirname "$0")"
CPP='cpp -undef -E -P crash_dump.policy.def'
arches=( \
  "arm"      "-D__arm__" \
  "arm64"    "-D__aarch64__ -D__LP64__" \
  "riscv64"  "-D__riscv -D__LP64__" \
  "x86"      "-D__i386__" \
  "x86_64"   "-D__x86_64__ -D__LP64__" \
)

function generate_header() {
  HEADER=\
"# This file was auto-generated for the architecture ${1}.
# Do not modify this file directly.
# To regenerate all policy files run:
#   cd system/core/debuggerd/seccomp_policy
#   ./generate.sh
"
}

# Normal pass
for ((i = 0; i < ${#arches[@]}; i = i + 2)); do
  arch=${arches[$i]}
  arch_defines=${arches[$((i+1))]}
  echo "Generating normal policy for ${arch}"
  file="crash_dump.${arch}.policy"
  ${CPP} ${arch_defines} -o ${file}
  generate_header ${arch}
  echo -e "${HEADER}$(cat ${file})" > ${file}
done

# Generate version without mmap/mprotect/prctl rules
# This is needed for swcodec to be able to include the policy file since that
# process requires a more permissive version of these syscalls.
for ((i = 0; i < ${#arches[@]}; i = i + 2)); do
  arch=${arches[$i]}
  arch_defines=${arches[$((i+1))]}
  echo "Generating no mmap/mprotect/prctl policy for ${arch}"
  file="crash_dump.no_mmap_mprotect_prctl.${arch}.policy"
  ${CPP} ${arch_defines} -DNO_MMAP_MPROTECT_PRCTL_RULES -o ${file}
  generate_header ${arch}
  echo -e "${HEADER}$(cat ${file})" > ${file}
done
