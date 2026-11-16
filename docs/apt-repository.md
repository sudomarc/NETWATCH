# NETWATCH NG APT repository setup

The signed repository publication workflow is
`.github/workflows/publish-apt.yml`. It publishes only after a stable
GitHub Release with a tag matching `v2.X.Y`.

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

The private key is imported into a temporary GnuPG home during a workflow
run. The signing workflows do not print or publish the private key or
passphrase.

## 3. Enable GitHub Pages

In repository Settings → Pages, set the deployment source to **GitHub Actions**.

The publication workflow uses the `github-pages` environment and requires
`pages: write` and `id-token: write` permissions.

## 4. Validate the signing secrets without publishing

After adding all three secrets, open Actions → **Validate NETWATCH NG APT
signing key** → Run workflow.

This manual workflow:

1. Imports the private key into a temporary GnuPG home.
2. Confirms that its primary fingerprint matches `APT_GPG_KEY_ID`.
3. Signs temporary Release metadata with detached and clear signatures.
4. Verifies both signatures in a separate GnuPG home containing only the
   exported public key.
5. Deletes its temporary key material when the job ends.

It does not create a GitHub Release or deploy to GitHub Pages.

## 5. Publish a stable release

Only publish after the Debian package build, unit tests, E2E tests and the
manual signing-key validation have passed.

Create a GitHub Release using a stable `v2.X.Y` tag, for example
`v2.0.0`. The workflow rejects malformed, non-stable or non-2.x tags.

The release workflow synchronizes the Python project version in its
temporary checkout with the release tag, creates the matching Debian
changelog version, runs unit and E2E tests, builds the package and checks
both Debian and Python package metadata versions before signing.

The publication workflow then:

1. Builds the Debian `.deb` package.
2. Generates the `Packages`, `Packages.gz` and `Release` indexes.
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
has completed and the public key, index and package signature have been
verified from a clean client machine.
