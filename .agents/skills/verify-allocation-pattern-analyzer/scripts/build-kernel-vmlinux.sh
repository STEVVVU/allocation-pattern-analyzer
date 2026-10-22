#!/usr/bin/env bash
set -euo pipefail

output_dir=${1:?usage: build-kernel-vmlinux.sh OUTPUT_DIR}
version=${2:-6.6}
case "$version" in
    6.6) source_sha256="d926a06c63dd8ac7df3f86ee1ffc2ce2a3b81a2d168484e76b5b389aba8e56d0" ;;
    6.1) source_sha256="2ca1f17051a430f6fed1196e4952717507171acfd97d96577212502703b25deb" ;;
    *) printf 'only pinned official Linux 6.1 and 6.6 are supported\n' >&2; exit 1 ;;
esac
if [[ -e "$output_dir" || -L "$output_dir" ]]; then
    printf 'output path already exists; choose a new directory: %s\n' "$output_dir" >&2
    exit 1
fi
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
archive="$output_dir/linux-$version.tar.xz"
source_dir="$output_dir/linux-$version"
source_url="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$version.tar.xz"

curl --fail --location --retry 2 "$source_url" --output "$archive"
printf '%s  %s\n' "$source_sha256" "$archive" | sha256sum --check --status
tar -xJf "$archive" -C "$output_dir"
make -C "$source_dir" ARCH=x86_64 tinyconfig
scripts_config="$source_dir/scripts/config"
"$scripts_config" --file "$source_dir/.config" --enable KALLSYMS --enable KALLSYMS_ALL
make -C "$source_dir" ARCH=x86_64 olddefconfig
make -C "$source_dir" ARCH=x86_64 -j2 vmlinux
test -s "$source_dir/vmlinux"
file "$source_dir/vmlinux" | grep -q 'ELF 64-bit LSB.*x86-64'
{
    printf 'source_url=%s\nsource_version=%s\nsource_tar_sha256=%s\n' "$source_url" "$version" "$source_sha256"
    printf 'kernel_release=%s\n' "$(make -s -C "$source_dir" ARCH=x86_64 kernelversion)"
    sha256sum "$source_dir/.config" "$source_dir/vmlinux"
    grep -E '^CONFIG_(64BIT|X86_64|KALLSYMS|KALLSYMS_ALL)=' "$source_dir/.config"
    cc --version
    ld --version
} > "$output_dir/source-provenance.txt"
