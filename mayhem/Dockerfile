# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org base image
# (ghcr.io/mayhemheroes/base). The base provides debian + clang/llvm + libFuzzer + Python 3 + the
# identities + the build-contract ENV. tinycss2 is a PURE-PYTHON package (a tiny CSS parser; its
# only dependency is the pure-Python `webencodings`), so this image installs the Atheris harness's
# Python deps (atheris + the tinycss2 package with its `test` extra: pytest, ruff) into the base's
# system Python as root, then (as the non-root `mayhem` user) compiles the ELF launcher shims and
# runs the full upstream pytest suite via build.sh / test.sh.
#
# Build (from the repo root, with the tests/css-parsing-tests submodule checked out):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t tinycss2-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH
# Declared for parity with the build contract; tinycss2 has no native code to sanitize.
ARG SANITIZER_FLAGS

# Atheris (the libFuzzer harness engine — builds a native module against the base's clang/libFuzzer)
# goes into the base's SYSTEM Python. PEP 668 marks that interpreter externally-managed, so
# --break-system-packages. This is the (networked) install step; build.sh deliberately does NOT
# pip-install, so its offline PATCH-tier re-run stays air-gapped.
USER root
RUN pip install --no-cache-dir --break-system-packages atheris==3.1.0

# Source enters from the build CONTEXT (the CI checkout, incl. the tests/css-parsing-tests
# submodule): the FULL repo (incl. .git history) is copied to /mayhem; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# The upstream suite's known-answer corpus lives in the tests/css-parsing-tests git submodule.
# A bare clone/checkout context carries only the gitlink, so fetch the contents here (networked
# Dockerfile step — build.sh stays offline). No-op when the context already includes them.
RUN git config --global --add safe.directory '*' && \
    git submodule update --init tests/css-parsing-tests && \
    test -f 'tests/css-parsing-tests/An+B.json'
RUN chown -R 2000:2000 tests/css-parsing-tests && { chown -R 2000:2000 .git/modules 2>/dev/null || true; }

# Install tinycss2 itself with its test extra (pytest, ruff; runtime dep webencodings) so the
# harness can `import tinycss2` and test.sh can run the full upstream suite.
RUN pip install --no-cache-dir --break-system-packages '.[test]'

USER mayhem

# Compile the ELF launcher shims (Mayhem needs an ELF target, not a .py).
RUN bash mayhem/build.sh

# Run tinycss2's entire upstream pytest suite at build time; a failing suite fails the build.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
