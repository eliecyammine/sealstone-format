#!/bin/sh
# Everything CI runs, run here first.
#
# The point is that a push should never be the thing that discovers a problem.
# This repository had no such script, so the only way to run what CI runs was
# to push and wait, and the slow job in particular was something nobody saw
# until it had already failed.
#
#   Scripts/ci-local.sh            everything, including the slow family
#   Scripts/ci-local.sh fast       skip the production-parameter family
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GREEN='\033[0;32m'; RED='\033[0;31m'; DIM='\033[2m'; OFF='\033[0m'
ok()   { printf "  ${GREEN}pass${OFF}  %s\n" "$1"; }
fail() { printf "  ${RED}FAIL${OFF}  %s\n" "$1"; exit 1; }
step() { printf "\n${DIM}%s${OFF}\n" "$1"; }

ONLY="${1:-all}"

# ─────────────────────────────────────────────────────── dependencies

step "Dependencies"

# This package installs nothing. A dependency file appearing means that
# changed, and the whole claim of the reference decoder is that it shares no
# code, and no supply chain, with the app.
if ls requirements*.txt pyproject.toml setup.py 2>/dev/null | grep -q .; then
  fail "a dependency file exists; this package installs nothing"
fi
ok "standard library only"

# ─────────────────────────────────────────────────────── tests

step "Decoder"
(cd decoder && python3 -m unittest discover -s tests -t . >/dev/null 2>&1) \
  || { (cd decoder && python3 -m unittest discover -s tests -t . 2>&1 | tail -30); fail "tests"; }
ok "tests pass"

# ─────────────────────────────────────────────────────── corpus

step "Vectors"

# The corpus is generated deterministically: salts, nonces and Shamir
# coefficients come from each family's identifier. Regenerating must produce
# byte-identical files, so a diff here means either generation stopped being
# deterministic or the encoder changed. Both are worth knowing before a push.
before=$(find vectors -name '*.seal' -o -name '*.json' | sort | xargs shasum -a 256 | shasum -a 256)
python3 vectors/generate.py >/dev/null
after=$(find vectors -name '*.seal' -o -name '*.json' | sort | xargs shasum -a 256 | shasum -a 256)
if [ "$before" != "$after" ]; then
  git --no-pager diff --stat
  fail "regenerating the corpus produced different bytes"
fi
ok "corpus is byte-identical after regeneration"

if [ "$ONLY" = "fast" ]; then
  printf "\n${GREEN}Everything but the slow family passes here.${OFF}\n"
  printf "${DIM}CI also runs it. Run without 'fast' before pushing.${OFF}\n"
  exit 0
fi

# ─────────────────────────────────────────────────────── slow

step "Production parameters"

# Argon2id at 64 MiB in pure Python, which is where the minutes go. It runs
# because the parameters that ship should not be the least tested thing here,
# and because CI runs it: a local check that skips what the runner does is a
# local check that says "safe to push" and is wrong.
(cd decoder && SEALSTONE_SLOW_TESTS=1 python3 -m unittest discover -s tests -t . >/dev/null 2>&1) \
  || { (cd decoder && SEALSTONE_SLOW_TESTS=1 python3 -m unittest discover -s tests -t . 2>&1 | tail -30); fail "tests at production parameters"; }
ok "tests pass at production parameters"

printf "\n${GREEN}Everything CI runs passes here. Safe to push.${OFF}\n"
