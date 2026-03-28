import { build } from 'esbuild';

// Main SDK bundle (workflow API + format internals for inspection)
await build({
  entryPoints: ['src/demo-bundle.ts'],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'browser',
  outfile: '../../demo/cef-sdk.js',
});

// PQ module (ML-KEM + ML-DSA)
await build({
  entryPoints: ['src/format/pq.ts'],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'browser',
  outfile: '../../demo/cef-pq.js',
});

// Timestamp module
await build({
  entryPoints: ['src/timestamp/timestamp.ts'],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'browser',
  outfile: '../../demo/cef-timestamp.js',
});

// Certificate module (self-signed ML-DSA-65 cert generation)
await build({
  entryPoints: ['src/x509/cert.ts'],
  bundle: true,
  format: 'esm',
  target: 'es2022',
  platform: 'browser',
  outfile: '../../demo/cef-cert.js',
});

console.log('Built demo bundles');
