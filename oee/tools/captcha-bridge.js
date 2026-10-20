#!/usr/bin/env node
'use strict';

// Node bridge — deobfuscated ফাইল থেকে captcha config পড়ে encrypt/decrypt করে
//
// Usage:
//   node captcha-bridge.js <deobf-file> encrypt <startAt> <length> <version> <secret-hex> <rawToken>
//   node captcha-bridge.js <deobf-file> decrypt <startAt> <length> <version> <secret-hex> <encToken>
//   node captcha-bridge.js <deobf-file> config
//   echo "<rawToken>" | node captcha-bridge.js <deobf-file> encrypt-stdin

const fs = require('fs');
const vm = require('vm');
const path = require('path');

function die(msg, code = 1) {
  process.stderr.write(String(msg) + '\n');
  process.exit(code);
}

// deobf ফাইল থেকে AH (version → module path) এবং mW.getCaptchaEncryptConfig() extract করা
// আসল ফাইলে সব "p1".."B5" modules object-এ `AH` নামে থাকে।
// আমরা সরাসরি ফাইলটা sandbox-এ চালাই না (window/document লাগবে)।
// পরিবর্তে AST-free regex দিয়ে সেই ১০টা module-এর ফাংশন extract করি।

// ─── Simple approach: ইউজার আমাদের সব encrypt ফাংশন একটা inline JS bundle দেয় ───
// এটা সহজ রাখতে আমরা চাই ইউজার আগেই এই ফাইলটা বানিয়ে দিক:
//
//   tools/captcha-extracted.js  — শুধু ১০টা module + alphabet + helpers
//
// সেটা বানানোর জন্য একটা helper script নিচে দিচ্ছি (extract-captcha.js)

const extractedPath = path.join(__dirname, 'captcha-extracted.js');
if (!fs.existsSync(extractedPath)) {
  die(`missing ${extractedPath}\n` +
      `প্রথমে extract-captcha.js চালিয়ে captcha-extracted.js বানান`);
}

// ── Extracted module-টা sandbox-এ লোড করা
const ctx = vm.createContext(Object.create(null), {
  codeGeneration: { strings: true, wasm: false }, // eval দরকার (module-গুলো eval-free, তবে safe)
});

try {
  new vm.Script(fs.readFileSync(extractedPath, 'utf8'), {
    filename: 'captcha-extracted.js',
  }).runInContext(ctx, { timeout: 5000 });
} catch (e) {
  die('failed to load captcha-extracted.js: ' + e.message);
}

if (typeof ctx.encryptText !== 'function' || typeof ctx.decryptText !== 'function') {
  die('captcha-extracted.js must export encryptText & decryptText');
}

const [, , deobfFile, cmd, ...rest] = process.argv;
if (!deobfFile || !cmd) {
  die('usage: node captcha-bridge.js <deobf-file> <config|encrypt|decrypt|encrypt-stdin> [args...]');
}

// ── config extract
if (cmd === 'config') {
  const src = fs.readFileSync(deobfFile, 'utf8');
  const block = src.match(
    /secret\s*:\s*"([^"]+)"\s*,\s*startAt\s*:\s*Number\(\s*"?(\d+)"?\s*\)\s*,\s*length\s*:\s*Number\(\s*"?(\d+)"?\s*\)\s*,\s*version\s*:\s*Number\(\s*"?(\d+)"?\s*\)/
  );
  if (!block) {
    // fallback loose
    const sec = src.match(/secret\s*:\s*"([^"]+)"/);
    if (!sec) die('secret not found');
    const sa = src.match(/startAt\s*:\s*(?:Number\(\s*)?"?(\d+)"?/);
    const le = src.match(/length\s*:\s*(?:Number\(\s*)?"?(\d+)"?/);
    const ve = src.match(/version\s*:\s*(?:Number\(\s*)?"?(\d+)"?/);
    process.stdout.write(JSON.stringify({
      secret: sec[1],
      startAt: sa ? +sa[1] : 6,
      length: le ? +le[1] : 25,
      version: ve ? +ve[1] : 5,
    }));
    process.exit(0);
  }
  process.stdout.write(JSON.stringify({
    secret: block[1],
    startAt: +block[2],
    length: +block[3],
    version: +block[4],
  }));
  process.exit(0);
}

// ── encrypt / decrypt
const [startAtStr, lengthStr, versionStr, secretHex, ...tokenParts] = rest;
const startAt = +startAtStr;
const length = +lengthStr;
const version = +versionStr;

if (cmd === 'encrypt-stdin') {
  // read token from stdin
  const chunks = [];
  process.stdin.on('data', c => chunks.push(c));
  process.stdin.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8').trim();
    const secret = Buffer.from(secretHex, 'hex').toString('utf8');
    if (typeof ctx.setConfig === 'function') ctx.setConfig(secret, startAt, length, version);
    else if (typeof ctx.configure === 'function') ctx.configure({ secret, startAt, length, version });
    process.stdout.write(ctx.encryptText(raw));
  });
  return;
}

const secret = Buffer.from(secretHex, 'hex').toString('utf8');
let token = tokenParts.join(' ');

if (typeof ctx.setConfig === 'function') ctx.setConfig(secret, startAt, length, version);
else if (typeof ctx.configure === 'function') ctx.configure({ secret, startAt, length, version });

if (cmd === 'encrypt') {
  process.stdout.write(ctx.encryptText(token));
} else if (cmd === 'decrypt') {
  process.stdout.write(ctx.decryptText(token));
} else {
  die('unknown cmd: ' + cmd);
}