'use strict';

const fs = require('fs');
const path = require('path');

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function copyFile(src, dest) {
  ensureDir(path.dirname(dest));
  fs.copyFileSync(src, dest);
}

function main() {
  const root = path.resolve(__dirname, '..');
  const srcFile = path.join(root, 'src', 'secure_demo.js');
  const outDir = path.join(root, 'dist');
  const outFile = path.join(outDir, 'secure_demo.js');

  if (!fs.existsSync(srcFile)) {
    throw new Error(`Missing source file: ${srcFile}`);
  }

  ensureDir(outDir);
  copyFile(srcFile, outFile);

  // Also emit a minimal package.json for consumers (optional but convenient).
  const pkgOut = {
    name: 'secure-js-samples-dist',
    private: true,
    main: './secure_demo.js'
  };
  fs.writeFileSync(path.join(outDir, 'package.json'), JSON.stringify(pkgOut, null, 2) + '\n', 'utf8');

  process.stdout.write(`Built: ${path.relative(root, outFile)}\n`);
}

main();
