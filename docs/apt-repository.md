# NETWATCH NG APT repository setup

The repository uses a single GitHub Actions workflow:
`.github/workflows/ci.yml`. It runs CI checks for pushes and pull requests,
and publishes the signed APT repository only when a stable GitHub Release
with a tag matching `v2.X.Y` is published.

The same workflow checks the legacy Bash/TUI components, NETWATCH NG on
Python 3.10–3.12, and Debian package build/install smoke tests on Debian 12
and 13. Its release job validates the release tag, repeats the NETWATCH NG
unit and end-to-end tests, then builds and verifies the release package
before signing and deploying the APT repository.

## 1. Create a dedicated archive signing key

Create a dedicated GPG key for APT repository signing. Keep the private key
outside the repository and protect it with a strong passphrase.

```bash
gpg --full-generate-key
gpg --list-secret-keys --keyid-format=long
gpg --armor --export-secret-keys YOUR_KEY_FINGERPRINT > netwatch-ng-archive-private.asc
gpg --armor --export YOUR_KEY_FINGERPRINT > netwatch-ng-archive-public.asc
```

Do not commit either key file.

## 2. Configure GitHub Actions secrets

In repository Settings → Secrets and variables → Actions, create:

- `APT_GPG_PRIVATE_KEY`: the ASCII-armored private key contents.
- `APT_GPG_KEY_ID`: the full 40-character primary-key fingerprint.
- `APT_GPG_PASSPHRASE`: the key passphrase.

The release job imports the private key into a temporary GnuPG home.
It verifies that the imported key matches `APT_GPG_KEY_ID`, signs the APT
metadata, and verifies both signatures with the exported public key. Temporary
key material is removed when the workflow finishes.

## 3. Enable GitHub Pages

In repository Settings → Pages, set the deployment source to **GitHub Actions**.

The release job uses the `github-pages` environment and requires
`pages: write` and `id-token: write` permissions.

## 4. Validate changes before a release

The single workflow runs automatically for pull requests and pushes to
the supported development branches. It checks the legacy Bash and TUI code,
runs NETWATCH NG unit and end-to-end tests across Python 3.10–3.12, and builds,
installs, and smoke-tests the Debian package on Debian 12 and 13.

No separate manual signing-key workflow is required. The release job
performs the key fingerprint check and cryptographic signing verification
before anything is deployed.

To publish or retry an existing stable release manually, open Actions → CI →
Run workflow, select `main`, and enter the tag in `release_tag` (for example
`v2.1.0`). Leave `release_tag` empty to run CI checks only. The selected tag
must match the stable `v2.X.Y` format.

## 5. Publish a stable release

Publish only after the unified CI checks have passed.

Create a GitHub Release using a stable `v2.X.Y` tag, for example `v2.0.0`.
The release job rejects malformed, non-stable, or non-2.x tags.

The workflow synchronizes the Python project version in its temporary
checkout with the release tag, creates the matching Debian changelog version,
runs NETWATCH NG unit and end-to-end tests, builds the package, and checks both
Debian and Python package metadata versions before signing.

The release job then:

1. Builds the Debian `.deb` package.
2. Generates the `Packages`, `Packages.gz`, and `Release` indexes.
3. Signs `InRelease` and `Release.gpg`.
4. Verifies both signatures using the exported public key.
5. Publishes the repository and public key through GitHub Pages.

## 6. Install on Debian/antiX amd64

After the first Pages deployment succeeds, add the public key and repository:

```bash
curl -fsSL https://sudomarc.github.io/NETWATCH/public.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/netwatch-ng-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/netwatch-ng-archive-keyring.gpg] https://sudomarc.github.io/NETWATCH/ stable main" \
  | sudo tee /etc/apt/sources.list.d/netwatch-ng.list

sudo apt update
sudo apt install netwatch-ng
```

The repository index targets Debian `amd64` systems. The `.deb` itself is
an architecture-independent Python package.

Do not treat the repository as ready until the first real Pages deployment
has completed and the public key, index, and package signature have been
verified from a clean client machine.
