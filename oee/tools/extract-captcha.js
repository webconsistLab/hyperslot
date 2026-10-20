#!/usr/bin/env node
'use strict';

// deobf ফাইল থেকে শুধু captcha-এর ১০টা encrypt module + helpers বের করে
// captcha-extracted.js বানায় (eval-safe, window-free)।

const fs = require('fs');
const path = require('path');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');

const [, , inputFile, outputFile] = process.argv;
if (!inputFile || !outputFile) {
  console.error('usage: node extract-captcha.js <deobf.js> <captcha-extracted.js>');
  process.exit(2);
}

const src = fs.readFileSync(inputFile, 'utf8');
const ast = parser.parse(src, {
  sourceType: 'unambiguous',
  errorRecovery: true,
  plugins: ['jsx', 'typescript', 'classProperties', 'objectRestSpread'],
});

// আমরা একটা "keep" set বানাই সেই সব top-level var/function এর জন্য
// যেগুলো captcha encrypt-এ লাগে। নাম দিয়ে খুঁজি (obf ফাইলে fixed নাম):
//   alphabet ($0, y1, _4, H1, f2, g1, e5, n5, V1, ...)  ← সব version-এ আলাদা
//   helper funcs: r1, o1, s1, w1, A1, O1, N1, z1, R1, $1, e4, W4, m4, M4, G4,
//                 z4, Z4, t2, n2, k2, x2, y2, L2, K2, Q2, r5, o5, N5, G5,
//                 f4, Y1, X0/$0/y1/_4/H1/... alphabet consts
//
// এই নামগুলো আপনার ফাইলে যেভাবে আছে সেটার উপর নির্ভর করে।

// সবচেয়ে নিরাপদ উপায়: ফাইলের শেষে থাকা self-test block আর PH() ফাংশন থেকে
// সব module-এর নাম বের করা।
//
// PH = function (e, t) {
//   const { secret: o, startAt: i, length: a, version: c } = t;
//   const s = $e.useRef(null);
//   const [l, d] = $e.useState(false);
//   ...
//   const o = AH[c];          // ← AH → version → module
//   o().then(o => {
//     s.current = o.encryptText;   // ← encryptText name
//   });
//   ...
//   const n = s.current;
//   if (n && !(e === null)) W(n(e, o, i, a));    // ← এটা main encrypt call
//   ...
// };

// AH object-টা খুঁজি:
//   const AH = { 1: () => Xe(() => Promise.resolve().then(() => p1)), ... }
// বা:
//   const AH = {1: () => Xe(() => Promise.resolve().then(() => p1)), 2: () => Xe(...)}

let AH = null;
let alphabetConsts = new Set();
let mainFunc = null; // PH

traverse(ast, {
  VariableDeclarator(p) {
    // AH object
    if (t.isIdentifier(p.node.id) && t.isObjectExpression(p.node.init)) {
      const props = p.node.init.properties;
      let allGood = props.length === 10;
      const entries = {};
      for (const prop of props) {
        if (!t.isObjectProperty(prop)) { allGood = false; break; }
        const key = t.isNumericLiteral(prop.key) ? String(prop.key.value)
                  : t.isStringLiteral(prop.key) ? prop.key.value : null;
        if (!key) { allGood = false; break; }
        // value: () => Xe(() => Promise.resolve().then(() => p1))
        // অথবা: () => Promise.resolve().then(...)
        // শেষের Identifier টা বের করি
        let fn = null;
        t.traverseFast(prop.value, n => {
          if (t.isIdentifier(n) && /^[A-Za-z_$][\w$]*$/.test(n.name)) {
            // শেষের দিকের identifier
            fn = n.name;
          }
        });
        entries[key] = fn;
      }
      if (allGood && Object.keys(entries).length === 10) {
        AH = entries;
      }
    }
  },
});

if (!AH) {
  console.error('AH object (version → module) not found.');
  process.exit(1);
}

// alphabet constants — সব "0123456789abc...-_" strings
const alphabets = new Set();
traverse(ast, {
  StringLiteral(p) {
    if (p.node.value === '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_') {
      // identifier যেটার assigned
      const parent = p.parentPath;
      if (parent.isVariableDeclarator() && t.isIdentifier(parent.node.id)) {
        alphabets.add(parent.node.id.name);
      }
    }
  },
});

// ── এখন আমরা সব "keep" ফাংশন/var collect করি
// এই নামগুলো captcha-এর সাথে সংশ্লিষ্ট — সব version + helpers + alphabets
const keep = new Set([
  // alphabet consts
  ...alphabets,
  // v1 (p1)
  'r1', 'o1', 's1', 'e1',
  // v2 (L1)  — same as z1/R1, w1, A1, O1, N1
  'z1', 'R1', 'w1', 'A1', 'O1', 'N1',
  // v3 (i4)
  '$1', 'e4',
  // v4 (S4)
  'W4', 'm4', 'f4',
  // v5 (V4)
  'M4', 'G4', 'z4',
  // v6 (d2)
  'Z4', 't2', 'n2',
  // v7 (N2)
  'k2', 'x2', 'y2',
  // v8 (Y2)
  'L2', 'K2', 'Q2',
  // v9 (v5)
  'r5', 'o5', 's5', 'W5',
  // v10 (B5)
  'N5', 'G5', 'R5',
  // d4 / _4 / H1 / b5 etc
]);

// প্রতিটি version-এর module-টা একটা object যেখানে encryptText/decryptText আছে।
// যেমন: const p1 = Object.freeze(Object.defineProperty({
//   __proto__: null,
//   decryptText: s1,
//   encryptText: o1
// }, Symbol.toStringTag, { value: "Module" }));

const modNames = new Set(Object.values(AH).filter(Boolean));

// সব module + keep ফাংশন Babel দিয়ে collect করি
const collected = new Map(); // name → node
const pending = new Set();

function addName(name) {
  if (collected.has(name) || pending.has(name)) return;
  pending.add(name);
}

for (const m of modNames) addName(m);
for (const n of keep) addName(n);

// AST scan: যে কোনো VariableDeclarator / FunctionDeclaration যার name ∈ pending
let changed = true;
while (changed) {
  changed = false;
  traverse(ast, {
    VariableDeclarator(p) {
      if (!t.isIdentifier(p.node.id)) return;
      const name = p.node.id.name;
      if (!pending.has(name)) return;
      if (collected.has(name)) return;
      collected.set(name, p.node);
      pending.delete(name);
      changed = true;
      // referenced identifiers add করি (only function bodies)
      p.traverse({
        ReferencedIdentifier(ip) {
          const bn = ip.node.name;
          if (!collected.has(bn) && bn !== name) addName(bn);
        },
      });
    },
    FunctionDeclaration(p) {
      if (!t.isIdentifier(p.node.id)) return;
      const name = p.node.id.name;
      if (!pending.has(name)) return;
      if (collected.has(name)) return;
      collected.set(name, p.node);
      pending.delete(name);
      changed = true;
      p.traverse({
        ReferencedIdentifier(ip) {
          const bn = ip.node.name;
          if (!collected.has(bn) && bn !== name) addName(bn);
        },
      });
    },
  });
}

// এখন একটা جدید program বানাই: শুধু collected nodes + global bindings
const outBody = [];
for (const [, node] of collected) {
  if (t.isFunctionDeclaration(node)) {
    outBody.push(node);
  } else if (t.isVariableDeclarator(node)) {
    outBody.push(t.variableDeclaration('var', [node]));
  }
}

// ── AH-কে একটা function-এ expose করি
// version → module-name map
const ahJSON = JSON.stringify(AH);
outBody.push(t.variableDeclaration('var', [
  t.variableDeclarator(t.identifier('__AH'),
    t.callExpression(t.identifier('JSON.parse'), [t.stringLiteral(ahJSON)])),
]));

// ── الآن configure + encryptText + decryptText wrap করি
const wrapper = `
// ─── node bridge wrapper (auto-generated) ───
var __currentConfig = { secret: "", startAt: 6, length: 25, version: 5 };
function setConfig(secret, startAt, length, version) {
  __currentConfig = { secret, startAt, length, version };
}
function configure(cfg) {
  __currentConfig = Object.assign({}, __currentConfig, cfg);
}
function encryptText(text) {
  var v = __currentConfig.version;
  var modName = __AH[String(v)];
  if (!modName) throw new Error("unknown version: " + v);
  var mod = eval(modName);
  return mod.encryptText(text, __currentConfig.secret, __currentConfig.startAt, __currentConfig.length);
}
function decryptText(text) {
  var v = __currentConfig.version;
  var modName = __AH[String(v)];
  if (!modName) throw new Error("unknown version: " + v);
  var mod = eval(modName);
  return mod.decryptText(text, __currentConfig.secret, __currentConfig.startAt, __currentConfig.length);
}
`;

outBody.push(t.raw ? t.raw(wrapper) : parser.parse(wrapper).program.body[0]);

// generate
const newProg = t.program(outBody);
const out = generate(newProg, { comments: false, compact: false }).code;

fs.writeFileSync(outputFile, out, 'utf8');
console.log('[+] wrote', outputFile, '(' + out.length + ' bytes)');
console.log('[+] versions found:', Object.keys(AH).join(', '));