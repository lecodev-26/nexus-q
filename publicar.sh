#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
ROOT="$(cd -- "$(dirname -- "$BASH_SOURCE")" && pwd)"
cd "$ROOT"
say() { printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { say "ERROR: $*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Falta el comando requerido: $1"; }
has_token() { eval "[[ -n \$$1 ]]" || die "Falta la variable $1 en $CONFIG"; }
run() { say "+ $*"; "$@"; }
# Fail closed before creating logs or touching a registry. A release run is tied
# to the exact annotated v4.1.2 tag and a pristine checkout.
need git
[[ "$(git status --porcelain --untracked-files=all)" == "" ]] || die "El árbol de trabajo no está limpio; no se publicará nada."
[[ "$(git cat-file -t refs/tags/v4.1.2 2>/dev/null || true)" == "tag" ]] || die "Se requiere el tag anotado v4.1.2; no se crea ni mueve ningún tag."
TAG_COMMIT="$(git rev-parse 'refs/tags/v4.1.2^{}')"
HEAD_COMMIT="$(git rev-parse HEAD)"
[[ "$HEAD_COMMIT" == "$TAG_COMMIT" ]] || die "HEAD ($HEAD_COMMIT) no coincide con el commit del tag v4.1.2 ($TAG_COMMIT)."
VERSION="$(sed -n 's/^version = \"\([^\"]*\)\"/\1/p' Cargo.toml | head -n1)"
[[ "$VERSION" == "4.1.2" ]] || die "Se requiere versión Cargo 4.1.2; se detectó '$VERSION'."
need curl
need python
need gh
gh auth status >/dev/null 2>&1 || die "gh no está autenticado; se necesita para verificar la release GitHub."

# The remote tag must be annotated and peel to exactly the local release commit.
REMOTE_TAGS="$(git ls-remote --tags origin "refs/tags/v$VERSION" "refs/tags/v$VERSION^{}")" || die "No se pudieron verificar los tags remotos de origin."
REMOTE_TAG_OBJECT="$(printf '%s\n' "$REMOTE_TAGS" | awk -v ref="refs/tags/v$VERSION" '$2 == ref {print $1}')"
REMOTE_TAG_COMMIT="$(printf '%s\n' "$REMOTE_TAGS" | awk -v ref="refs/tags/v$VERSION^{}" '$2 == ref {print $1}')"
[[ -n "$REMOTE_TAG_OBJECT" && -n "$REMOTE_TAG_COMMIT" ]] || die "El tag remoto v$VERSION debe existir y ser anotado."
[[ "$REMOTE_TAG_COMMIT" == "$TAG_COMMIT" ]] || die "El tag remoto v$VERSION apunta a $REMOTE_TAG_COMMIT, no al commit local $TAG_COMMIT."

# Publishing is allowed only when the already-created GitHub release manifest
# identifies this exact HEAD and release version.
TEMP_RELEASE="$(mktemp -d "${TMPDIR:-/tmp}/nexusq-release-manifest.XXXXXX")"
cleanup() { rmdir "$LOCK_DIR" 2>/dev/null || true; rm -rf "$TEMP_RELEASE"; }
LOCK_DIR="${TMPDIR:-/tmp}/nexusq-publish-v4.1.2.lock"
mkdir "$LOCK_DIR" 2>/dev/null || die "Ya existe otro proceso de publicación o un lock pendiente: $LOCK_DIR"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
gh release download "v$VERSION" --repo lecodev-26/nexus-q --pattern release-manifest.json --dir "$TEMP_RELEASE" >/dev/null || die "No se pudo descargar release-manifest.json de la release GitHub v$VERSION."
python - "$TEMP_RELEASE/release-manifest.json" "$HEAD_COMMIT" "$VERSION" <<'PYMANIFEST' || die "release-manifest.json no coincide con HEAD y la versión esperada."
import json, sys
from pathlib import Path
manifest = json.loads(Path(sys.argv[1]).read_text())
expected_commit, expected_version = sys.argv[2:4]
if manifest.get("commit") != expected_commit:
    raise SystemExit(f"manifest commit {manifest.get('commit')!r} != HEAD {expected_commit!r}")
if manifest.get("version") != expected_version:
    raise SystemExit(f"manifest version {manifest.get('version')!r} != {expected_version!r}")
PYMANIFEST
CONFIG="$HOME/.config/nexusq/publish.env"
DIST="$ROOT/.publish-dist"
mkdir -p "$DIST"
LOG="$DIST/publish-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
[[ -f "$CONFIG" ]] || die "No existe $CONFIG. Crea el archivo privado de credenciales."
chmod 600 "$CONFIG" 2>/dev/null || true
# shellcheck disable=SC1090
source "$CONFIG"
for cmd in git curl python cargo gh; do need "$cmd"; done
say "NEXUS-Q v$VERSION — publicación manual"
say "Log: $LOG"
curl -fsSL "https://api.github.com/repos/lecodev-26/nexus-q/releases/tags/v$VERSION" >/dev/null || die "No existe el release GitHub v$VERSION."

# Validate every local prerequisite before the first irreversible registry push.
for cmd in maturin twine npm gem dart mvn gpg; do need "$cmd"; done
for key in CRATES_IO_TOKEN PYPI_TOKEN NPM_TOKEN RUBYGEMS_API_KEY PACKAGIST_USERNAME PACKAGIST_API_TOKEN; do has_token "$key"; done
[[ -f "$HOME/.m2/settings.xml" ]] || die "Falta ~/.m2/settings.xml con el servidor central y credenciales."
gpg --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec:' || die "Maven Central exige una clave GPG privada importada."


# Rust crates: dependency order and already-published checks.
has_token CRATES_IO_TOKEN
export CARGO_REGISTRY_TOKEN="$CRATES_IO_TOKEN"
run python .github/scripts/publish_crates.py

# Python: publish the sdist from Termux. Do not fabricate foreign-platform wheels.
need maturin
need twine
has_token PYPI_TOKEN
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="$PYPI_TOKEN"
rm -rf "$DIST/python"
mkdir -p "$DIST/python"
run maturin sdist --manifest-path crates/nexusq-py/Cargo.toml --out "$DIST/python"
find "$DIST/python" -maxdepth 1 -type f | grep -q . || die "maturin no ha generado el sdist."
run twine check "$DIST"/python/*
run twine upload --non-interactive --skip-existing "$DIST"/python/*

# npm / TypeScript.
need npm
has_token NPM_TOKEN
export NODE_AUTH_TOKEN="$NPM_TOKEN"
run npm --prefix bindings/typescript ci --ignore-scripts
run npm --prefix bindings/typescript run build
if npm view "nexusq@$VERSION" version >/dev/null 2>&1; then
  say "npm: nexusq@$VERSION ya existe; se omite."
else
  run npm --prefix bindings/typescript publish --access public --ignore-scripts
fi

# RubyGems.
need gem
has_token RUBYGEMS_API_KEY
mkdir -p "$DIST/ruby"
( cd bindings/ruby && gem build nexusq.gemspec --output "$DIST/ruby/nexusq-$VERSION.gem" )
if curl -fsSL "https://rubygems.org/api/v2/rubygems/nexusq/versions/$VERSION.json" >/dev/null 2>&1; then
  say "RubyGems: nexusq $VERSION ya existe; se omite."
else
  GEM_HOST_API_KEY="$RUBYGEMS_API_KEY" gem push "$DIST/ruby/nexusq-$VERSION.gem" --host https://rubygems.org
fi

# Dart uses the existing pub.dev login in Termux.
need dart
run dart pub token list
if curl -fsSL "https://pub.dev/api/packages/nexusq/versions/$VERSION" >/dev/null 2>&1; then
  say "pub.dev: nexusq $VERSION ya existe; se omite."
else
  run dart pub publish --force --directory bindings/dart
fi

# PHP / Packagist: validate manifest and request repository refresh.
has_token PACKAGIST_USERNAME
has_token PACKAGIST_API_TOKEN
if command -v composer >/dev/null 2>&1; then
  run composer validate --no-check-publish
else
  say "AVISO: composer no está instalado; se omite solo la validación local del manifiesto."
fi
curl -fsS --config - <<PACKAGIST_CURL || die "Packagist no ha aceptado la actualización."
url = "https://packagist.org/api/update-package?username=$PACKAGIST_USERNAME&apiToken=$PACKAGIST_API_TOKEN"
request = "POST"
header = "Content-Type: application/json"
data = "{\"repository\":{\"url\":\"https://github.com/lecodev-26/nexus-q\"}}"
PACKAGIST_CURL

# Maven Central: requires Central Portal token pair in ~/.m2/settings.xml and imported GPG private key.
need mvn
need gpg
[[ -f "$HOME/.m2/settings.xml" ]] || die "Falta ~/.m2/settings.xml con servidor central y credenciales."
gpg --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec:' || die "Maven Central exige clave GPG privada importada."
maven_version_exists() {
  local artifact="$1"
  local response
  response="$(curl -fsSL "https://search.maven.org/solrsearch/select?q=g:%22io.github.lecodev-26%22%20AND%20a:%22$artifact%22%20AND%20v:%22$VERSION%22&rows=1&wt=json")" || die "No se pudo consultar Maven Central; no arriesgo un duplicado."
  printf '%s' "$response" | python -c 'import json,sys; data=json.load(sys.stdin); sys.exit(0 if data["response"]["numFound"] else 1)'
}
if maven_version_exists nexusq; then
  say "Maven Central: io.github.lecodev-26:nexusq:$VERSION ya existe; se omite."
else
  run mvn -B -f bindings/java/pom.xml clean deploy
fi
if maven_version_exists nexusq-kotlin; then
  say "Maven Central: io.github.lecodev-26:nexusq-kotlin:$VERSION ya existe; se omite."
else
  run mvn -B -f bindings/kotlin/pom.xml clean deploy
fi

# NuGet must stay in GitHub Actions with OIDC; never use a local API key.
say "Lanzando workflow OIDC de NuGet"
run gh workflow run publish-nuget.yml --ref "v$VERSION"

# Go and Swift are distributed from the repository's versioned tags.
git rev-parse "refs/tags/v$VERSION" >/dev/null 2>&1 || say "AVISO: no existe tag local v$VERSION; Go/Swift dependen de tags GitHub."
say "Ejecución terminada; revisa los resultados y el workflow NuGet."
