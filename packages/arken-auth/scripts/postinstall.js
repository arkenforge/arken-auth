#!/usr/bin/env node
'use strict';

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const pkg = path.join(__dirname, '..');
const rustDir = path.join(pkg, 'rust');
const binDir = path.join(pkg, 'bin');

function checkCargo() {
    try {
        execSync('cargo --version', { stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
}

function libName() {
    const ext = { win32: '.dll', darwin: '.dylib' }[os.platform()] ?? '.so';
    const prefix = os.platform() === 'win32' ? '' : 'lib';
    return `${prefix}arken_core${ext}`;
}

console.log('[arken-auth] Building native library...');

if (!checkCargo()) {
    console.error(
        '[arken-auth] Rust toolchain not found.\n' +
        'Install Rust from https://rustup.rs and re-run: npm install'
    );
    process.exit(1);
}

try {
    execSync('cargo build --release', {
        cwd: rustDir,
        stdio: 'inherit',
        env: { ...process.env }
    });
} catch (err) {
    console.error('[arken-auth] Rust build failed. See output above.');
    process.exit(1);
}

if (!fs.existsSync(binDir)) fs.mkdirSync(binDir, { recursive: true });

const src = path.join(rustDir, 'target', 'release', libName());
const dst = path.join(binDir, libName());

fs.copyFileSync(src, dst);
console.log(`[arken-auth] Native library built → bin/${libName()}`);
