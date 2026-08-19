# Publishing checklist

## 1. Cut a release (produces the install tarball)

The awesome-dsh-plugin entry installs from a prebuilt tarball attached to a
GitHub release. Tag a version to trigger `.github/workflows/release.yml`:

```sh
git tag v0.1.0
git push origin v0.1.0
```

CI builds `dist/dshn-agent`, packs it, and attaches `dshn-agent.tgz` to the
release. Verify the tarball resolves:

```sh
curl -IL https://github.com/jsdvjx/dshn/releases/latest/download/dshn-agent.tgz
```

## 2. Repo hygiene (awesome-dsh-plugin requirements)

- [x] `dsh.bundle` manifest in `packages/agent/package.json` (and the shipped tarball)
- [x] `cordis.patch.yml` present with an `insert:` list
- [x] Real, working code (relay + agent + protocol, with tests)
- [x] `LICENSE` (MIT)
- [ ] **Add the `dsh-plugin` topic** to the GitHub repo (Settings → Topics)
- [ ] Repo is **≥ 1 day old with 10+ commits** (registry anti-spam gate — the PR
      below will fail CI until this is met, so submit after the repo has aged a day)

## 3. Submit to the registry

The entry file is prepared at [`publish/jsdvjx__dshn.yml`](./publish/jsdvjx__dshn.yml).

```sh
git clone https://github.com/awesome-dsh-plugin/awesome-dsh-plugin
cd awesome-dsh-plugin
cp /path/to/dshn/publish/jsdvjx__dshn.yml data/plugins/jsdvjx__dshn.yml
npm ci && node scripts/generate-readme.mjs   # regenerate the READMEs
git checkout -b add-dshn
git add data/plugins/jsdvjx__dshn.yml README*.md
git commit -m "Add jsdvjx/dshn (remote)"
gh pr create --title "Add jsdvjx/dshn" --body "DeepSeek Harness Network — public forwarding for a local dsh over *.ds.hn."
```

Their CI verifies: manifest presence, repo age, README generation, lint. Category
is `remote` (Remote & Mobile). An inaccurate description is sent back to fix, not
rejected.

## 4. Optional: screenshots

Screenshots must be GitHub-hosted and are added to `data/screenshots.json` in the
registry repo, keyed by this repo's URL. Use clean captures with **no private
session/workspace data** (the local dsh sidebar shows real conversation titles —
crop them out or use a throwaway profile). Not yet prepared.
