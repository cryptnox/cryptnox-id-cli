#!/usr/bin/env bash
# Local CI mirror. Runs the GitHub Actions jobs on your machine via Docker, using
# python:X-slim images. No git, no runner, no reader: unit tests run against the
# mock transport.
#
# Usage:
#   scripts/test-local.sh                   # everything: all jobs, full matrix
#   scripts/test-local.sh 3.10 3.14         # limit the pytest matrix to these
#   scripts/test-local.sh --test-only 3.10  # pytest only, no lint/typecheck/build/docs
#
# Jobs mirrored:
#   lint       once    ruff check + format --check, pinned ruff   (.github/workflows/ci.yml)
#   typecheck  once    mypy                                        (ci.yml)
#   test       matrix  pytest, mock transport                      (ci.yml)
#   build      once    python -m build                             (ci.yml)
#   docs       once    sphinx-build -W, HTML only                  (.github/workflows/docs.yml)
#
# The default matrix covers every Python version the package declares, which is
# wider than CI's 3.10 + 3.14. The docs job builds HTML only; the PDF step in
# docs.yml needs a full LaTeX install and is not mirrored.
#
# pyscard is a C extension with no Linux wheel, so any job that pip-installs the
# package first installs the build toolchain (build-essential swig libpcsclite-dev).
set -euo pipefail

# --test-only: run just the pytest matrix, skip lint/typecheck/build/docs.
TEST_ONLY=0
if [[ "${1:-}" == "--test-only" ]]; then
  TEST_ONLY=1
  shift
fi

# Per-version matrix. Default: every version in pyproject.toml's classifiers.
if [[ $# -gt 0 ]]; then
  VERSIONS=("$@")
else
  VERSIONS=(3.10 3.11 3.12 3.13 3.14)
fi

# Version used for the run-once jobs (matches CI).
PRIMARY=3.12
RUFF_PIN=0.15.16

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail=0

# run <label> <fail-on-error 0|1> <python-ver> <bash-script>
run() {
  local label=$1 hard=$2 ver=$3 script=$4
  echo "==================== ${label} (py${ver}) ===================="
  # ':ro,z' - z relabels for SELinux, else the container can't read the mount.
  # The repo is copied into the container rather than used in place, so no job
  # writes to your checkout. .git and everything .gitignore covers stays behind:
  # .git mutates whenever git runs on the host (index.lock), and local venvs,
  # caches and build output would only slow the copy and could mask a clean build.
  if docker run --rm -v "${REPO_ROOT}:/src:ro,z" -w /work "python:${ver}-slim" \
      bash -c "set -e; tar -cf - -C /src \
        --exclude='./.git' --exclude='./.venv' --exclude='./venv' --exclude='./env' \
        --exclude='./build' --exclude='./dist' --exclude='./docs/_build' \
        --exclude='*.egg-info' --exclude='__pycache__' \
        --exclude='.mypy_cache' --exclude='.pytest_cache' --exclude='.ruff_cache' \
        . | tar -xf - -C /work; ${script}"; then
    echo "PASS ${label}"
  else
    echo "FAIL ${label}"
    if [[ "${hard}" == 1 ]]; then fail=1; else echo "  (informational - not failing the run)"; fi
  fi
}

# Snippet installing the pyscard build toolchain.
PCSC_INSTALL='apt-get update -qq && apt-get install -y --no-install-recommends build-essential swig libpcsclite-dev >/dev/null'

# --- lint (once) ---
if [[ "${TEST_ONLY}" == 0 ]]; then
run "lint" 1 "${PRIMARY}" "
  pip install -q ruff==${RUFF_PIN}
  ruff check src tests
  ruff format --check src tests
"
fi

# --- test (matrix) ---
for ver in "${VERSIONS[@]}"; do
  run "test" 1 "${ver}" "
    ${PCSC_INSTALL}
    python --version
    pip install -q -e '.[dev]'
    pytest -q -m 'not real_card'
  "
done

if [[ "${TEST_ONLY}" == 0 ]]; then

# --- typecheck (once; a failure fails CI, so it fails here too) ---
run "typecheck" 1 "${PRIMARY}" "
  ${PCSC_INSTALL}
  pip install -q -e . mypy
  mypy
"

# --- build (once) ---
run "build" 1 "${PRIMARY}" "
  pip install -q build
  python -m build
"

# --- docs (once) ---
run "docs" 1 "${PRIMARY}" "
  pip install -q -r docs/requirements.txt
  sphinx-build -W --keep-going -b html docs docs/_build/html
"

fi  # end TEST_ONLY guard

echo "========================================================"
if [[ "${fail}" == 0 ]]; then echo "ALL PASS"; else echo "FAILURES above"; fi
exit "${fail}"
