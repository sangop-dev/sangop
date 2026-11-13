# Third-party licences (Sangop 2026.11.0)

Generated 13 Nov 2026 with `pip-licenses` in two clean virtual environments (Python 3.13): one with `pip install .` (what a normal user gets) and one with `pip install ".[dev]"` (adds the optional FastMCP integration, PyYAML for policy packs, and the test tools). Regenerate before every release:

```
python -m venv .lic && .lic/bin/pip install ".[dev]" pip-licenses
.lic/bin/pip-licenses --format=markdown --with-urls --ignore-packages pip-licenses prettytable wcwidth pip sangop
```

Sangop itself is Apache-2.0. Declared dependencies (`pyproject.toml`): runtime `sqlglot>=28.5`; optional `fastmcp>=2` (extra `fastmcp`), `pyyaml>=6` (extra `policy`); development `pytest>=8`, `fastmcp>=2`, `pyyaml>=6`, `httpx>=0.28` (extra `dev`); build backend `hatchling`. Media M0 (`sangop.media`) uses only the Python standard library.

## Result in one line

**No GPL, AGPL, LGPL, SSPL or other strong-copyleft licence was found** in either environment (1 runtime package, 68 packages in the full development tree). One weak-copyleft item (certifi, MPL-2.0) appears only in the optional/dev tree. Licence strings come from each package's own metadata and are not independently audited; this is an engineering record, not legal advice.

## 1. Runtime dependencies (installed with `pip install sangop`)

| Package | Version | Licence (from package metadata) | URL |
|---|---|---|---|
| sqlglot | 30.31.0 | MIT | https://sqlglot.com/ |

## 2. Optional / development dependencies (`sangop[fastmcp]`, `sangop[policy]`, `sangop[dev]`)

| Package | Version | Licence (from package metadata) | URL |
|---|---|---|---|
| aiofile | 3.12.3 | Apache-2.0 | https://github.com/mosquito/aiofile |
| annotated-types | 0.8.0 | MIT | https://github.com/annotated-types/annotated-types |
| anyio | 4.16.0 | MIT | https://anyio.readthedocs.io/en/stable/versionhistory.html |
| attrs | 26.1.0 | MIT | https://www.attrs.org/en/stable/changelog.html |
| Authlib | 1.9.5 | BSD (variant not stated in metadata: verify) | https://github.com/authlib/authlib |
| beartype | 0.23.1 | MIT | - |
| cachetools | 8.0.0 | MIT | https://github.com/tkem/cachetools/ |
| caio | 0.12.10 | Apache-2.0 | - |
| certifi | 2026.10.23 | MPL-2.0 (file-level copyleft, see note) | https://github.com/certifi/python-certifi |
| cffi | 2.1.1 | MIT-0 | https://cffi.readthedocs.io/en/latest/whatsnew.html |
| click | 8.5.1 | BSD-3-Clause | https://github.com/pallets/click/ |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| cyclopts | 5.4.2 | Apache-2.0 | https://github.com/BrianPugh/cyclopts |
| dnspython | 2.9.2 | ISC | https://www.dnspython.org |
| docstring_parser | 0.18.0 | MIT License | https://github.com/rr-/docstring_parser |
| email-validator | 2.3.0 | The Unlicense (Unlicense) | https://github.com/JoshData/python-email-validator |
| exceptiongroup | 1.3.1 | MIT License | https://github.com/agronholm/exceptiongroup/blob/main/CHANGES.rst |
| fastmcp | 4.2.0 | Apache-2.0 | https://gofastmcp.com |
| fastmcp-slim | 4.2.0 | Apache-2.0 | https://gofastmcp.com |
| griffelib | 2.4.1 | ISC | https://mkdocstrings.github.io/griffe |
| h11 | 0.16.0 | MIT License | https://github.com/python-hyper/h11 |
| httpcore | 1.0.9 | BSD-3-Clause | https://www.encode.io/httpcore/ |
| httpcore2 | 2.16.0 | BSD-3-Clause | https://github.com/pydantic/httpx2 |
| httpx2 | 2.16.0 | BSD-3-Clause | https://github.com/pydantic/httpx2 |
| idna | 3.20 | BSD-3-Clause | https://github.com/kjd/idna |
| iniconfig | 2.3.1 | MIT | https://github.com/pytest-dev/iniconfig |
| joserfc | 1.8.0 | BSD (variant not stated in metadata: verify) | https://github.com/authlib/joserfc |
| jsonref | 1.1.0 | MIT | https://github.com/gazpachoking/jsonref |
| jsonschema | 4.26.0 | MIT | https://github.com/python-jsonschema/jsonschema |
| jsonschema-path | 0.5.0 | Apache Software License | https://github.com/p1c2u/jsonschema-path |
| jsonschema-specifications | 2025.9.1 | MIT | https://github.com/python-jsonschema/jsonschema-specifications |
| markdown-it-py | 4.3.0 | MIT License | https://github.com/executablebooks/markdown-it-py |
| mcp | 2.3.0 | MIT License | https://modelcontextprotocol.io |
| mcp-types | 2.3.0 | MIT License | https://modelcontextprotocol.io |
| mdurl | 0.1.2 | MIT License | https://github.com/executablebooks/mdurl |
| openapi-pydantic | 0.6.0 | MIT License | https://github.com/mike-oakley/openapi-pydantic |
| opentelemetry-api | 1.45.2 | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-api |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | https://github.com/pypa/packaging |
| pathable | 0.6.0 | Apache Software License | https://github.com/p1c2u/pathable |
| platformdirs | 4.14.5 | MIT | https://github.com/tox-dev/platformdirs |
| pluggy | 1.7.0 | MIT License | https://github.com/pytest-dev/pluggy |
| py-key-value-aio | 0.4.6 | Apache-2.0 | - |
| pycparser | 3.12 | BSD-3-Clause | https://github.com/eliben/pycparser |
| pydantic | 2.14.3 | MIT | https://github.com/pydantic/pydantic |
| pydantic-settings | 2.16.3 | MIT | https://github.com/pydantic/pydantic-settings |
| pydantic_core | 2.50.4 | MIT | https://github.com/pydantic |
| Pygments | 2.21.0 | BSD-2-Clause | https://pygments.org |
| PyJWT | 2.15.1 | MIT | https://github.com/jpadilla/pyjwt |
| pyperclip | 1.11.0 | BSD (variant not stated in metadata: verify) | https://github.com/asweigart/pyperclip |
| pytest | 9.2.0 | MIT | https://docs.pytest.org/en/latest/ |
| python-dotenv | 1.2.4 | BSD-3-Clause | https://github.com/theskumar/python-dotenv |
| python-multipart | 0.0.33 | Apache-2.0 | https://github.com/Kludex/python-multipart |
| PyYAML | 6.0.3 | MIT License | https://pyyaml.org/ |
| referencing | 0.37.0 | MIT | https://github.com/python-jsonschema/referencing |
| rich | 15.0.0 | MIT License | https://github.com/Textualize/rich |
| rich-rst | 2.2.0 | MIT | https://wasi-master.github.io/rich-rst |
| rpds-py | 2026.9.1 | MIT | https://github.com/crate-py/rpds |
| sse-starlette | 3.7.0 | BSD-3-Clause | https://github.com/sysid/sse-starlette |
| starlette | 1.10.0 | BSD-3-Clause | https://github.com/Kludex/starlette |
| truststore | 0.10.5 | MIT | https://github.com/sethmlarson/truststore |
| typing-inspection | 0.4.5 | MIT | https://github.com/pydantic/typing-inspection |
| typing_extensions | 4.16.0 | PSF-2.0 | https://github.com/python/typing_extensions |
| uncalled-for | 0.6.1 | MIT | https://github.com/chrisguidry/uncalled-for |
| uvicorn | 0.54.0 | BSD-3-Clause | https://uvicorn.dev/ |
| watchfiles | 1.3.0 | MIT License | https://github.com/samuelcolvin/watchfiles |
| websockets | 17.4 | BSD-3-Clause | https://github.com/python-websockets/websockets |

## 3. Build and test-only tools (not installed with Sangop, never shipped in the wheel)

| Package | Version | Licence (from package metadata) | URL | Why |
|---|---|---|---|---|
| hatchling | 1.33.0 | MIT | https://hatch.pypa.io/latest/ | build backend (`[build-system]`) |
| httpx | 0.28.1 | BSD (variant not stated in metadata: verify) | https://github.com/encode/httpx | in the `dev` extra since 11 Nov 2026, for the MCP compatibility tests (brings `httpcore`, listed above); never installed with Sangop itself |

## Notes

* **certifi (MPL-2.0)** is a transitive dependency of the HTTP stack that FastMCP brings in. MPL-2.0 is file-level copyleft: it only affects modifications to certifi's own files. Sangop does not bundle or modify it. It is not installed with the base package.
* Entries marked "BSD (variant not stated in metadata: verify)" declare only the generic classifier "BSD License" (Authlib, httpx, joserfc, pyperclip); open the package's LICENSE file before any redistribution that bundles it.
* Versions are the ones pip chose on 13 Nov 2026; a fresh install may pick newer ones. Tools used only for the project's internal benchmark comparisons are not dependencies and are not part of this repository.
* Test-only packages are never shipped inside the Sangop wheel.
