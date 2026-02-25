#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 4 ]]; then
  echo "usage: $0 <target> <version> [binary_path] [output_dir]" >&2
  exit 1
fi

target="$1"
version="$2"
binary_path="${3:-sigmund}"
output_dir="${4:-dist}"
stage_dir="${output_dir}/package-${target}"
archive_name="sigmund-${version}-${target}.tar.gz"

rm -rf "${stage_dir}"
mkdir -p "${stage_dir}" "${output_dir}"
cp "${binary_path}" "${stage_dir}/sigmund"
chmod +x "${stage_dir}/sigmund"

shopt -s nullglob
for file in LICENSE* README*; do
  cp -a "${file}" "${stage_dir}/"
done
shopt -u nullglob

tar -C "${stage_dir}" -czf "${output_dir}/${archive_name}" .

echo "${output_dir}/${archive_name}"
