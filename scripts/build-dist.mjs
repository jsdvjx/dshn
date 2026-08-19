// Produce self-contained, shippable artifacts under dist/:
//   dist/dshn/   — the dsh plugin, ws + @dshn/protocol inlined, cordis and
//                        schemastery left external (dsh provides them at runtime)
//   dist/relay/relay.mjs — the relay as one file (what gets deployed to a server)
// Bundling frees `dsh plugin add` from resolving the file:../protocol workspace
// link, and frees the relay host from needing any npm install.
import { readdirSync, mkdirSync, copyFileSync, writeFileSync, rmSync } from 'node:fs'

const root = process.cwd()
const ebDir = readdirSync('node_modules/.pnpm').find((d) => d.startsWith('esbuild@'))
if (!ebDir) throw new Error('esbuild not found under node_modules/.pnpm')
const esbuild = (await import(`${root}/node_modules/.pnpm/${ebDir}/node_modules/esbuild/lib/main.js`)).default

const banner = { js: "import{createRequire as __cr}from'module';const require=__cr(import.meta.url);" }
const nativeOptional = ['bufferutil', 'utf-8-validate']

rmSync('dist', { recursive: true, force: true })

// ── agent plugin ────────────────────────────────────────────────────────────
mkdirSync('dist/dshn/lib', { recursive: true })
await esbuild.build({
  entryPoints: ['packages/agent/lib/index.js'],
  bundle: true, platform: 'node', target: 'node20', format: 'esm',
  outfile: 'dist/dshn/lib/index.js',
  // The agent imports nothing from dsh (it types ctx as any), so the bundle is
  // fully self-contained: ws and @dshn/protocol are inlined, and only the
  // optional native ws accelerators stay external.
  external: [...nativeOptional],
  banner,
})
copyFileSync('packages/agent/client.js', 'dist/dshn/client.js')
copyFileSync('packages/agent/cordis.patch.yml', 'dist/dshn/cordis.patch.yml')
copyFileSync('README.md', 'dist/dshn/README.md')
copyFileSync('LICENSE', 'dist/dshn/LICENSE')
writeFileSync('dist/dshn/package.json', JSON.stringify({
  name: '@dshn/agent',
  version: '0.1.2',
  description: 'Forward a local dsh web service to the public internet over ds.hn (bundled).',
  keywords: ['dsh', 'dsh-plugin', 'deepseek-harness', 'tunnel', 'forwarding', 'ds.hn'],
  license: 'MIT',
  author: 'jsdvjx',
  homepage: 'https://github.com/jsdvjx/dshn#readme',
  bugs: 'https://github.com/jsdvjx/dshn/issues',
  repository: { type: 'git', url: 'git+https://github.com/jsdvjx/dshn.git', directory: 'packages/agent' },
  type: 'module',
  main: 'lib/index.js',
  exports: { '.': './lib/index.js', './client': './client.js', './package.json': './package.json' },
  files: ['lib', 'client.js', 'cordis.patch.yml', 'README.md', 'LICENSE'],
  dsh: {
    bundle: { patch: 'cordis.patch.yml' },
    client: { platform: 'web', inject: ['@deepseek-ai/dsh-client-runtime', '@deepseek-ai/dsh-client-ui-layout'] },
  },
  // No runtime dependencies: schemastery, ws, and @dshn/protocol are all inlined
  // by esbuild, so `npm i dshn` (or `dsh plugin add dshn`) pulls a
  // single self-contained package. cordis is provided by the dsh host at runtime.
  peerDependencies: { '@deepseek-ai/cordis': '*' },
}, null, 2) + '\n')

// ── relay ─────────────────────────────────────────────────────────────────
mkdirSync('dist/relay', { recursive: true })
await esbuild.build({
  entryPoints: ['packages/relay/lib/index.js'],
  bundle: true, platform: 'node', target: 'node20', format: 'esm',
  outfile: 'dist/relay/relay.mjs',
  external: nativeOptional,
  banner,
})

console.log('dist built: dist/dshn (installable plugin), dist/relay/relay.mjs')
