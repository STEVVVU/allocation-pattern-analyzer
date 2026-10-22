# Dependency and native-extension provenance

The supported base is the angr `v9.2.207` release at Git commit `9037fb8c6ee4a2df61ba64b7a561373f5eb6b253`. The checked-out source and commit history remain intact. `requirements-ci.txt` freezes the Python dependency versions observed in the isolated Python 3.11 environment; the CI workflow also pins Python 3.11.9 and Rust 1.99.1.

The official PyPI release manifest identifies these build-critical artifacts by SHA-256:

| Artifact | SHA-256 | Use |
| --- | --- | --- |
| `angr-9.2.207.tar.gz` | `badddc89e925c4bec90e8669734671ec66da89a3380812be5bc9474bef3ec820` | Exact angr source built for Python 3.11; PyPI has no cp311 wheel for this release. |
| `pyvex-9.2.207-cp311-cp311-win_amd64.whl` | `cabf4b6734480343a9131d317dee85e8380e8184cd268ec67a8cd343e3e77622` | Matching Windows Python 3.11 dependency wheel used for local verification. |
| `pyvex-9.2.207-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | `6ce1a401a47bab3f651536c5a1e2e366160c38e3561535ca307ec863590b5186` | Matching Linux Python 3.11 dependency wheel selected by hosted CI. |
| `bitstring-4.3.1-py3-none-any.whl` | `69d1587f0ac18dc7d93fc7e80d5f447161a33e57027e726dc18a0a8bacf1711a` | Compatibility pin: bitstring 5.x removed `ConstBitStream` imported by angr 9.2.207. |

The local CPython 3.11 Windows wheel built from the exact angr source distribution has SHA-256 `a80d883d153ea443167d67fd4e44e66c89d4f9acd718d3ed90653050bf77570e` (7,666,510 bytes). Its native `angr.rustylib` extension and Unicorn binding were produced by the source build using Rust 1.99.1, Cargo 1.99.1, MSVC 14.44, and nmake. This locally built wheel is evidence of the Windows build, not an input to Linux CI; CI rebuilds from the same pinned source and toolchain. The separate Python `unicorn==2.1.4` dependency is present to avoid optional-engine import warnings; the analysis does not enable the Unicorn execution engine.

The isolated environment passed `pip check`. Exact package versions and compatibility constraints are frozen in `requirements-ci.txt`; artifact hashes above identify the release source, platform-specific pyvex wheels, compatibility pin, and locally built native-extension wheel. PyPI primary release manifests: [angr 9.2.207](https://pypi.org/pypi/angr/9.2.207/json), [pyvex 9.2.207](https://pypi.org/pypi/pyvex/9.2.207/json), and [bitstring 4.3.1](https://pypi.org/pypi/bitstring/4.3.1/json).

The first Linux source build reproduced the missing `ConstBitStream` error inside pip's isolated build environment. pip 26.2 separates runtime and build constraints, so CI passes the same exact constraints through both interfaces and pins pip 26.2.2. This preserves build isolation. See the [official build-constraint documentation](https://pip.pypa.io/en/stable/user_guide/#build-constraints).
