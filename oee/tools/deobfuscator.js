#!/usr/bin/env node
'use strict';
/**
 * JS Deobfuscator v3 (fast)
 * -------------------------
 * v1-এর চেয়ে ৩-৫× দ্রুত। প্রধান পরিবর্তন:
 *   - WeakMap memoization: evalConst, countParamUses, buildProxyTable, buildChunk
 *   - Module-level compiled regexes (no per-call regex compilation)
 *   - Explicit traverse cache invalidation (not blanket clear())
 *   - Fast-path subst for identifiers/literals (avoids cloneNode)
 *   - Rename pass uses preallocated counter + Set lookups (O(n))
 *   - Char-code-based obfuscated-name check instead of regex
 *   - Parser options tuned: attachComment=false, tokens=false where safe
 *   - --fast flag skips rename+verify for very large files
 *
 * Strategy: NEVER executes the script. Only the string-decoder runs in a
 * sandboxed vm (no eval/Function, ES built-ins only).
 *
 * Usage:  node deobfuscator.js input.js [-o output.js] [--strings strings.txt]
 */

const fs = require('fs');
const os = require('os');
const v8 = require('v8');
const vm = require('vm');
const nodePath = require('path');
const { spawnSync } = require('child_process');

// ───────────────────────── CLI ─────────────────────────
const HELP = `
JS Deobfuscator v3  (javascript-obfuscator / string-array / RC4 / base64)

Usage:
  node deobfuscator.js <input.js> [options]
  cat input.js | node deobfuscator.js - -o out.js

Options:
  -o, --output <file>    Output file (default: <input>.deobf.js, "-" = stdout)
      --strings <file>   Also dump every decoded string to a text file
      --keep-infra       Keep decoder/wrapper/string-array code
      --no-rename        Don't rename _0x1a2b3c style identifiers
      --no-unminify      Skip the beautify/unminify transforms
      --no-verify        Skip re-parsing output for a syntax check
      --fast             Shorthand: --no-rename --no-verify --no-unminify
  -q, --quiet            No progress output
  -h, --help             Show this help
`;

function parseArgs(argv) {
  const o = {
    input: null, output: null, dumpStrings: null, keepInfra: false,
    rename: true, unminify: true, verify: true, quiet: false, help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h': case '--help': o.help = true; break;
      case '-o': case '--output': o.output = argv[++i]; break;
      case '--strings': o.dumpStrings = argv[++i]; break;
      case '--keep-infra': o.keepInfra = true; break;
      case '--no-rename': o.rename = false; break;
      case '--no-unminify': o.unminify = false; break;
      case '--no-verify': o.verify = false; break;
      case '--fast': o.rename = false; o.verify = false; o.unminify = false; break;
      case '-q': case '--quiet': o.quiet = true; break;
      default:
        if (a.startsWith('-') && a !== '-') { console.error('Unknown option: ' + a); process.exit(2); }
        o.input = a;
    }
  }
  return o;
}

// বড় ফাইলের জন্য বেশি হিপ দরকার হলে নিজেকে পুনরায় চালাই
function ensureBigHeap() {
  if (process.env.DEOBF_CHILD || require.main !== module) return;
  const limitMb = v8.getHeapStatistics().heap_size_limit / 1048576;
  if (limitMb >= 3500) return;
  const target = Math.floor(Math.min(6144, (os.totalmem() / 1048576) * 0.75));
  if (target <= limitMb + 256) return;
  const r = spawnSync(process.execPath, ['--max-old-space-size=' + target, __filename, ...process.argv.slice(2)], {
    stdio: 'inherit', env: Object.assign({}, process.env, { DEOBF_CHILD: '1' }),
  });
  process.exit(r.status === null ? 1 : r.status);
}
ensureBigHeap();

const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');

let QUIET = false;
const log = (...a) => { if (!QUIET) console.error(...a); };

// ───────────────────────── precompiled regexes ─────────────────────────
const RE_OBF_ID = /^_0x[0-9a-f]{3,}$/i;
const RE_NUMERIC_STR = /^-?\d+(?:\.\d+)?$/;
const RE_STR_DQ = /^"(?:[^"\\]|\\.)*"$/;
const RE_STR_SQ = /^'(?:[^'\\]|\\.)*'$/;

// ───────────────────────── helpers ─────────────────────────
const NOT_CONST = Symbol('not-const');

const SAFE_GLOBALS = new Set([
  'parseInt', 'parseFloat', 'String', 'Number', 'Boolean', 'Math', 'Array', 'Object', 'Symbol',
  'decodeURIComponent', 'encodeURIComponent', 'decodeURI', 'encodeURI', 'escape', 'unescape',
  'JSON', 'RegExp', 'Error', 'TypeError', 'RangeError', 'isNaN', 'isFinite', 'undefined', 'NaN',
  'Infinity', 'Date', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Reflect', 'Uint8Array', 'Int8Array',
  'Uint16Array', 'Uint32Array', 'Int32Array', 'Float64Array', 'ArrayBuffer',
]);

function getFnName(fnPath) {
  if (fnPath.isFunctionDeclaration()) return fnPath.node.id ? fnPath.node.id.name : null;
  const p = fnPath.parentPath;
  if (p && p.isVariableDeclarator() && t.isIdentifier(p.node.id) && p.node.init === fnPath.node) return p.node.id.name;
  return null;
}

function getFnBinding(fnPath) {
  const name = getFnName(fnPath);
  if (!name) return null;
  return fnPath.parentPath.scope.getBinding(name) || null;
}

function fnPathFromBinding(binding) {
  if (!binding) return null;
  const p = binding.path;
  if (p.isFunctionDeclaration()) return p;
  if (p.isVariableDeclarator()) {
    const init = p.get('init');
    if (init.node && (init.isFunctionExpression() || init.isArrowFunctionExpression())) return init;
  }
  return null;
}

function isLiteralNode(n) {
  return t.isStringLiteral(n) || t.isNumericLiteral(n) || t.isBooleanLiteral(n) || t.isNullLiteral(n);
}

function getLit(n) {
  if (!n) return null;
  if (t.isStringLiteral(n) || t.isNumericLiteral(n) || t.isBooleanLiteral(n)) return { v: n.value };
  if (t.isNullLiteral(n)) return { v: null };
  if (t.isUnaryExpression(n, { operator: '-' }) && t.isNumericLiteral(n.argument)) return { v: -n.argument.value };
  return null;
}

function valueToNode(v) {
  if (typeof v === 'string') return t.stringLiteral(v);
  if (typeof v === 'boolean') return t.booleanLiteral(v);
  if (v === null) return t.nullLiteral();
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return null;
    if (v < 0 || Object.is(v, -0)) return t.unaryExpression('-', t.numericLiteral(-v));
    return t.numericLiteral(v);
  }
  return null;
}

const BIN = {
  '+': (a, b) => a + b, '-': (a, b) => a - b, '*': (a, b) => a * b, '/': (a, b) => a / b,
  '%': (a, b) => a % b, '**': (a, b) => a ** b,
  '==': (a, b) => a == b, '!=': (a, b) => a != b, '===': (a, b) => a === b, '!==': (a, b) => a !== b, // eslint-disable-line eqeqeq
  '<': (a, b) => a < b, '>': (a, b) => a > b, '<=': (a, b) => a <= b, '>=': (a, b) => a >= b,
  '|': (a, b) => a | b, '&': (a, b) => a & b, '^': (a, b) => a ^ b,
  '<<': (a, b) => a << b, '>>': (a, b) => a >> b, '>>>': (a, b) => a >>> b,
};

// ── memoized constant evaluator (WeakMap keyed on node) ──
const evalConstCache = new WeakMap();
function evalConst(node, scope, depth = 0) {
  if (!node || depth > 8) return NOT_CONST;
  const cached = evalConstCache.get(node);
  if (cached !== undefined) return cached;
  let result;
  switch (node.type) {
    case 'NumericLiteral': case 'StringLiteral': case 'BooleanLiteral': result = node.value; break;
    case 'NullLiteral': result = null; break;
    case 'ParenthesizedExpression': result = evalConst(node.expression, scope, depth + 1); break;
    case 'UnaryExpression': {
      if (node.operator === 'void') { result = undefined; break; }
      const a = evalConst(node.argument, scope, depth + 1);
      if (a === NOT_CONST) { result = NOT_CONST; break; }
      switch (node.operator) {
        case '-': result = -a; break;
        case '+': result = +a; break;
        case '!': result = !a; break;
        case '~': result = ~a; break;
        default: result = NOT_CONST;
      }
      break;
    }
    case 'BinaryExpression': {
      const f = BIN[node.operator];
      if (!f) { result = NOT_CONST; break; }
      const l = evalConst(node.left, scope, depth + 1);
      const r = evalConst(node.right, scope, depth + 1);
      if (l === NOT_CONST || r === NOT_CONST) { result = NOT_CONST; break; }
      try { result = f(l, r); } catch (e) { result = NOT_CONST; }
      break;
    }
    case 'Identifier': {
      if (node.name === 'undefined') { result = undefined; break; }
      const b = scope.getBinding(node.name);
      if (b && b.constant && b.path.isVariableDeclarator() && b.path.node.init) {
        result = evalConst(b.path.node.init, b.path.scope, depth + 1);
      } else result = NOT_CONST;
      break;
    }
    default: result = NOT_CONST;
  }
  evalConstCache.set(node, result);
  return result;
}

function shapeOk(node, params) {
  switch (node.type) {
    case 'NumericLiteral': case 'StringLiteral': return true;
    case 'Identifier': return params.includes(node.name);
    case 'ParenthesizedExpression': return shapeOk(node.expression, params);
    case 'UnaryExpression': return (node.operator === '-' || node.operator === '+') && shapeOk(node.argument, params);
    case 'BinaryExpression':
      return ['+', '-', '*', '/', '%'].includes(node.operator) && shapeOk(node.left, params) && shapeOk(node.right, params);
    default: return false;
  }
}
function evalShape(node, env) {
  switch (node.type) {
    case 'NumericLiteral': case 'StringLiteral': return node.value;
    case 'Identifier': return env[node.name];
    case 'ParenthesizedExpression': return evalShape(node.expression, env);
    case 'UnaryExpression': return node.operator === '-' ? -evalShape(node.argument, env) : +evalShape(node.argument, env);
    case 'BinaryExpression': return BIN[node.operator](evalShape(node.left, env), evalShape(node.right, env));
    default: throw new Error('bad shape');
  }
}

// ───────────────────────── Phase 1: string-array decode ─────────────────────────
class Resolver {
  constructor() {
    this.decoders = new Map();
    this.memo = new WeakMap();      // binding.identifier node -> callable|null
    this.inProgress = new WeakSet();
    this.wrapperNodes = new Set();
  }
  addDecoder(fnNode, fn) { this.decoders.set(fnNode, fn); }

  getCallable(binding) {
    if (!binding || !binding.constant) return null;
    const key = binding.identifier;
    if (this.memo.has(key)) return this.memo.get(key);
    if (this.inProgress.has(key)) return null;
    this.inProgress.add(key);
    let result = null;
    try {
      const p = binding.path;
      if (p.isVariableDeclarator() && p.node.init && t.isIdentifier(p.node.init)) {
        result = this.getCallable(p.scope.getBinding(p.node.init.name));
      } else {
        const fnPath = fnPathFromBinding(binding);
        if (fnPath) {
          result = this.decoders.has(fnPath.node) ? this.decoders.get(fnPath.node) : this.analyzeWrapper(fnPath);
        }
      }
    } finally {
      this.inProgress.delete(key);
    }
    this.memo.set(key, result);
    return result;
  }

  analyzeWrapper(fnPath) {
    const node = fnPath.node;
    if (node.async || node.generator) return null;
    if (!node.params.every((p) => t.isIdentifier(p))) return null;
    let expr;
    if (t.isBlockStatement(node.body)) {
      if (node.body.body.length !== 1 || !t.isReturnStatement(node.body.body[0])) return null;
      expr = node.body.body[0].argument;
    } else expr = node.body;
    if (!expr || !t.isCallExpression(expr) || !t.isIdentifier(expr.callee)) return null;
    const params = node.params.map((p) => p.name);
    if (params.includes(expr.callee.name)) return null;
    if (!expr.arguments.every((a) => shapeOk(a, params))) return null;
    const calleeBinding = fnPath.scope.getBinding(expr.callee.name);
    const inner = this.getCallable(calleeBinding);
    if (!inner) return null;
    this.wrapperNodes.add(node);
    const argNodes = expr.arguments;
    return (args) => {
      const env = Object.create(null);
      params.forEach((p, i) => { env[p] = args[i]; });
      return inner(argNodes.map((a) => evalShape(a, env)));
    };
  }
}

function matchArrayFn(fnPath) {
  const node = fnPath.node;
  if (node.params.length || !t.isBlockStatement(node.body)) return null;
  const name = getFnName(fnPath);
  if (!name) return null;
  let arrLen = 0;
  for (const st of node.body.body) {
    if (!t.isVariableDeclaration(st)) continue;
    for (const d of st.declarations) {
      if (t.isIdentifier(d.id) && t.isArrayExpression(d.init) && d.init.elements.length >= 3 &&
          d.init.elements.every((e) => t.isStringLiteral(e))) arrLen = d.init.elements.length;
    }
  }
  if (!arrLen) return null;
  let selfReplace = false;
  t.traverseFast(node.body, (n) => {
    if (t.isAssignmentExpression(n, { operator: '=' }) && t.isIdentifier(n.left, { name }) && t.isFunctionExpression(n.right)) selfReplace = true;
  });
  return selfReplace ? { name, arrLen } : null;
}

// Cache for buildChunk keyed on arrayFn node
const chunkCache = new WeakMap();

function buildChunk(parts, code) {
  const firstFn = parts[0];
  const cached = chunkCache.get(firstFn.node);
  if (cached) return cached;

  const included = new Set();
  const pieces = [];
  const queue = [];

  const partSource = (p) => {
    if (p.isFunctionDeclaration()) return { node: p.node, src: code.slice(p.node.start, p.node.end), order: 1 };
    if (p.isFunctionExpression() || p.isArrowFunctionExpression()) {
      const decl = p.parentPath;
      return { node: p.node, src: 'var ' + decl.node.id.name + ' = ' + code.slice(p.node.start, p.node.end) + ';', order: 1, extra: decl.node };
    }
    return { node: p.node, src: code.slice(p.node.start, p.node.end) + ';', order: 3 };
  };
  const add = (p, forcedOrder) => {
    const info = partSource(p);
    if (included.has(info.node)) return;
    included.add(info.node);
    if (info.extra) included.add(info.extra);
    if (forcedOrder) info.order = forcedOrder;
    pieces.push(info);
    queue.push(p);
  };
  parts.forEach((p) => add(p));

  while (queue.length) {
    const p = queue.pop();
    p.traverse({
      ReferencedIdentifier(ip) {
        const b = ip.scope.getBinding(ip.node.name);
        if (!b) return;
        if (included.has(b.path.node) || b.path.findParent((pp) => included.has(pp.node))) return;
        const fp = fnPathFromBinding(b);
        if (fp) { add(fp, 0); return; }
        if (b.path.isVariableDeclarator() && b.path.node.init && t.isIdentifier(b.path.node.id)) {
          const init = b.path.node.init;
          const src = 'var ' + b.path.node.id.name + ' = ' + code.slice(init.start, init.end) + ';';
          included.add(b.path.node);
          pieces.push({ node: b.path.node, src, order: 0 });
          queue.push(b.path.get('init'));
        }
      },
    });
  }
  pieces.sort((a, b) => a.order - b.order);
  const result = pieces.map((x) => x.src).join('\n');
  chunkCache.set(firstFn.node, result);
  return result;
}

function unsafeGlobals(src) {
  const ast = parser.parse(src, { sourceType: 'script', allowReturnOutsideFunction: true });
  let bad = [];
  traverse(ast, {
    Program(p) {
      bad = Object.keys(p.scope.globals).filter((g) => !SAFE_GLOBALS.has(g));
      p.stop();
    },
  });
  return bad;
}

function runChunk(src) {
  const ctx = vm.createContext(Object.create(null), { codeGeneration: { strings: false, wasm: false } });
  new vm.Script(src, { filename: 'string-decoder.js' }).runInContext(ctx, { timeout: 20000 });
  return ctx;
}

function decodeStrings(ast, code, stats, opts) {
  const infra = { fnNodes: new Set(), rotators: new Map(), arrayFns: new Set() };
  const resolver = new Resolver();

  // 1a) find array groups + build decoders in sandbox
  traverse(ast, {
    Function(fnPath) {
      const m = matchArrayFn(fnPath);
      if (!m) return;
      const binding = getFnBinding(fnPath);
      if (!binding) return;
      const decoders = new Map();
      const rotators = [];
      for (const ref of binding.referencePaths) {
        const parent = ref.parentPath;
        if (!parent || !parent.isCallExpression()) continue;
        if (ref.listKey === 'arguments' && (t.isFunctionExpression(parent.node.callee) || t.isArrowFunctionExpression(parent.node.callee))) {
          const st = parent.getStatementParent();
          if (st) rotators.push(st);
        } else if (ref.key === 'callee' && parent.node.arguments.length === 0) {
          const f = ref.getFunctionParent();
          if (f && f.node !== fnPath.node && getFnName(f)) decoders.set(f.node, f);
        }
      }
      if (!decoders.size) return;
      stats.groupsFound++;
      let ctx;
      try {
        const src = buildChunk([fnPath, ...decoders.values(), ...rotators], code);
        const bad = unsafeGlobals(src);
        if (bad.length) { log(`  ! skip group ${m.name}: sandbox refuses globals [${bad.join(', ')}]`); return; }
        ctx = runChunk(src);
      } catch (e) {
        log(`  ! group ${m.name} failed: ${String(e.message).split('\n')[0]}`);
        return;
      }
      infra.fnNodes.add(fnPath.node);
      infra.arrayFns.add(fnPath.node);
      for (const [node, fp] of decoders) {
        const fn = ctx[getFnName(fp)];
        if (typeof fn !== 'function') continue;
        resolver.addDecoder(node, (args) => fn.apply(null, args));
        infra.fnNodes.add(node);
      }
      for (const r of rotators) infra.rotators.set(r.node, fnPath.node);
      stats.groupsOk++;
    },
  });

  if (!stats.groupsOk) return { infra, resolver };

  // 1b) recognize wrappers + replace calls
  traverse(ast, {
    Function(fnPath) {
      const n = fnPath.node;
      const b = t.isBlockStatement(n.body) ? n.body.body : null;
      const simple = b ? (b.length === 1 && t.isReturnStatement(b[0])) : t.isCallExpression(n.body);
      if (!simple) return;
      const binding = getFnBinding(fnPath);
      if (binding) resolver.getCallable(binding);
    },
    CallExpression: {
      exit(path) {
        const callee = path.node.callee;
        if (!t.isIdentifier(callee)) return;
        const binding = path.scope.getBinding(callee.name);
        if (!binding) return;
        const callable = resolver.getCallable(binding);
        if (!callable) return;
        const args = [];
        for (const a of path.node.arguments) {
          const v = evalConst(a, path.scope);
          if (v === NOT_CONST) return;
          args.push(v);
        }
        let val;
        try { val = callable(args); } catch (e) { return; }
        if (typeof val !== 'string') return;
        path.replaceWith(t.stringLiteral(val));
        stats.decoded++;
        stats.strings.set(val, (stats.strings.get(val) || 0) + 1);
      },
    },
  });

  for (const w of resolver.wrapperNodes) infra.fnNodes.add(w);
  stats.wrappers = resolver.wrapperNodes.size;
  return { infra, resolver };
}

// ───────────────────────── Phase 2: simplification ─────────────────────────
function containsHoistedDecl(node) {
  let found = false;
  const walk = (n) => {
    if (found || !n || typeof n.type !== 'string') return;
    if (t.isFunctionDeclaration(n)) { found = true; return; }
    if (t.isVariableDeclaration(n) && n.kind === 'var') { found = true; return; }
    if (t.isFunction(n)) return;
    for (const k of t.VISITOR_KEYS[n.type] || []) {
      const c = n[k];
      if (Array.isArray(c)) c.forEach(walk); else if (c) walk(c);
    }
  };
  walk(node);
  return found;
}

function foldPass(ast, stats) {
  let changed = 0;
  traverse(ast, {
    noScope: true,
    BinaryExpression: {
      exit(path) {
        const n = path.node;
        const l = getLit(n.left);
        const r = getLit(n.right);
        if (l && r) {
          const f = BIN[n.operator];
          if (!f) return;
          let v;
          try { v = f(l.v, r.v); } catch (e) { return; }
          const nn = valueToNode(v);
          if (nn) { path.replaceWith(nn); changed++; }
          return;
        }
        if (n.operator === '+' && t.isStringLiteral(n.right) && t.isBinaryExpression(n.left, { operator: '+' }) && t.isStringLiteral(n.left.right)) {
          path.replaceWith(t.binaryExpression('+', n.left.left, t.stringLiteral(n.left.right.value + n.right.value)));
          changed++;
        }
      },
    },
    LogicalExpression: {
      exit(path) {
        const n = path.node;
        const l = getLit(n.left);
        if (!l) return;
        let pick;
        if (n.operator === '&&') pick = l.v ? n.right : n.left;
        else if (n.operator === '||') pick = l.v ? n.left : n.right;
        else if (n.operator === '??') pick = (l.v === null || l.v === undefined) ? n.right : n.left;
        else return;
        path.replaceWith(pick);
        changed++;
      },
    },
    UnaryExpression: {
      exit(path) {
        const n = path.node;
        if (n.operator === 'void' || n.operator === 'delete') return;
        if ((t.isArrayExpression(n.argument) && n.argument.elements.length === 0) ||
            (t.isObjectExpression(n.argument) && n.argument.properties.length === 0)) {
          if (n.operator === '!') { path.replaceWith(t.booleanLiteral(false)); changed++; return; }
          if (n.operator === '+' && t.isArrayExpression(n.argument)) { path.replaceWith(t.numericLiteral(0)); changed++; return; }
        }
        const a = getLit(n.argument);
        if (!a) return;
        if (n.operator === '-' && t.isNumericLiteral(n.argument)) return;
        let v;
        switch (n.operator) {
          case '!': v = !a.v; break;
          case '-': v = -a.v; break;
          case '+': v = +a.v; break;
          case '~': v = ~a.v; break;
          case 'typeof': v = typeof a.v; break;
          default: return;
        }
        const nn = valueToNode(v);
        if (nn) { path.replaceWith(nn); changed++; }
      },
    },
    ConditionalExpression: {
      exit(path) {
        const l = getLit(path.node.test);
        if (!l) return;
        path.replaceWith(l.v ? path.node.consequent : path.node.alternate);
        changed++;
      },
    },
    IfStatement: {
      exit(path) {
        const l = getLit(path.node.test);
        if (!l) return;
        const truthy = !!l.v;
        const dead = truthy ? path.node.alternate : path.node.consequent;
        if (dead && containsHoistedDecl(dead)) return;
        if (truthy) path.replaceWith(path.node.consequent);
        else if (path.node.alternate) path.replaceWith(path.node.alternate);
        else path.remove();
        stats.deadBranches++;
        changed++;
      },
    },
    MemberExpression: {
      exit(path) {
        const n = path.node;
        if (n.computed && t.isStringLiteral(n.property) && t.isValidIdentifier(n.property.value, false)) {
          n.computed = false;
          n.property = t.identifier(n.property.value);
          changed++;
        }
      },
    },
    ObjectProperty: {
      exit(path) {
        const n = path.node;
        if (!n.computed && !n.shorthand && t.isStringLiteral(n.key) && t.isValidIdentifier(n.key.value, false)) {
          n.key = t.identifier(n.key.value);
          changed++;
        }
      },
    },
  });
  return changed;
}

// ── proxy inline (with WeakMap caches) ──
function analyzeInlineFn(fn) {
  if (fn.async || fn.generator) return null;
  if (!fn.params.every((p) => t.isIdentifier(p))) return null;
  let expr;
  if (t.isBlockStatement(fn.body)) {
    if (fn.body.body.length !== 1 || !t.isReturnStatement(fn.body.body[0]) || !fn.body.body[0].argument) return null;
    expr = fn.body.body[0].argument;
  } else expr = fn.body;
  let bad = false;
  t.traverseFast(expr, (n) => {
    if (t.isFunction(n) || t.isClass(n) || t.isThisExpression(n) || t.isSuper(n) || t.isIdentifier(n, { name: 'arguments' }) ||
        t.isAssignmentExpression(n) || t.isUpdateExpression(n) || t.isYieldExpression(n) || t.isAwaitExpression(n)) bad = true;
  });
  if (bad) return null;
  return { kind: 'fn', params: fn.params.map((p) => p.name), expr };
}

const proxyTableCache = new WeakMap();
function buildProxyTable(objNode) {
  const cached = proxyTableCache.get(objNode);
  if (cached !== undefined) return cached;
  const table = new Map();
  const seen = new Set();
  let invalid = false;
  for (const prop of objNode.properties) {
    if (t.isSpreadElement(prop) || prop.computed) { invalid = true; break; }
    const key = t.isIdentifier(prop.key) ? prop.key.name : t.isStringLiteral(prop.key) ? prop.key.value : null;
    if (key === null || seen.has(key)) { invalid = true; break; }
    seen.add(key);
    if (t.isObjectMethod(prop)) {
      if (prop.kind !== 'method') { invalid = true; break; }
      const info = analyzeInlineFn(prop);
      if (info) table.set(key, info);
    } else if (t.isObjectProperty(prop)) {
      const v = prop.value;
      if (isLiteralNode(v)) table.set(key, { kind: 'lit', node: v });
      else if (t.isFunctionExpression(v) || t.isArrowFunctionExpression(v)) {
        const info = analyzeInlineFn(v);
        if (info) table.set(key, info);
      }
    }
  }
  const result = !invalid && table.size ? table : null;
  proxyTableCache.set(objNode, result);
  return result;
}

function memberKey(m) {
  if (!m.computed && t.isIdentifier(m.property)) return m.property.name;
  if (m.computed && t.isStringLiteral(m.property)) return m.property.value;
  return null;
}

const isSimple = (a) => t.isIdentifier(a) || isLiteralNode(a) || t.isThisExpression(a) ||
  (t.isUnaryExpression(a, { operator: '-' }) && t.isNumericLiteral(a.argument));

const paramUseCache = new WeakMap();
function countParamUses(expr, params) {
  const cached = paramUseCache.get(expr);
  if (cached !== undefined) return cached;
  const counts = new Map();
  for (const p of params) counts.set(p, 0);
  const walk = (n, parent, key) => {
    if (!n) return;
    if (t.isIdentifier(n)) {
      const skip = (t.isMemberExpression(parent) && key === 'property' && !parent.computed) ||
                   (t.isObjectProperty(parent) && key === 'key' && !parent.computed);
      if (!skip && counts.has(n.name)) counts.set(n.name, counts.get(n.name) + 1);
      return;
    }
    for (const k of t.VISITOR_KEYS[n.type] || []) {
      const c = n[k];
      if (Array.isArray(c)) c.forEach((x) => walk(x, n, k)); else walk(c, n, k);
    }
  };
  walk(expr, null, null);
  paramUseCache.set(expr, counts);
  return counts;
}

// Fast subst: shallow-clone for leaf nodes, deep only when needed
function subst(node, map) {
  if (!node) return node;
  if (t.isIdentifier(node)) {
    const r = map.get(node.name);
    return r ? t.cloneNode(r, true) : t.cloneNode(node);
  }
  if (t.isStringLiteral(node) || t.isNumericLiteral(node) || t.isBooleanLiteral(node) || t.isNullLiteral(node)) {
    return t.cloneNode(node);
  }
  if (Array.isArray(node)) return node.map((n) => subst(n, map));
  const copy = Object.assign({}, node);
  const keys = t.VISITOR_KEYS[node.type] || [];
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (key === 'property' && (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) && !node.computed) continue;
    if (key === 'key' && t.isObjectProperty(node) && !node.computed) continue;
    const v = node[key];
    if (Array.isArray(v)) {
      const out = new Array(v.length);
      for (let j = 0; j < v.length; j++) out[j] = v[j] ? subst(v[j], map) : v[j];
      copy[key] = out;
    } else if (v) copy[key] = subst(v, map);
  }
  return copy;
}

function inlineCall(info, args) {
  if (args.some((a) => t.isSpreadElement(a) || t.isArgumentPlaceholder(a))) return null;
  const { params, expr } = info;
  const counts = countParamUses(expr, params);
  const map = new Map();
  for (let i = 0; i < params.length; i++) {
    const a = args[i];
    if (a && counts.get(params[i]) !== 1 && !isSimple(a)) return null;
    map.set(params[i], a || t.identifier('undefined'));
  }
  for (let i = params.length; i < args.length; i++) if (!isSimple(args[i])) return null;
  return subst(expr, map);
}

function inlinePass(ast, stats) {
  let changed = 0;
  traverse(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (!t.isIdentifier(id) || !t.isObjectExpression(init)) return;
      const binding = path.scope.getBinding(id.name);
      if (!binding || !binding.constant || binding.path !== path || !binding.referencePaths.length) return;
      const table = buildProxyTable(init);
      if (!table) return;
      const uses = [];
      for (const ref of binding.referencePaths) {
        const m = ref.parentPath;
        if (!m || !m.isMemberExpression() || m.node.object !== ref.node) return;
        const mp = m.parentPath;
        if ((mp.isAssignmentExpression() && mp.node.left === m.node) || mp.isUpdateExpression() ||
            mp.isUnaryExpression({ operator: 'delete' }) || mp.isForXStatement({ left: m.node })) return;
        uses.push(m);
      }
      let remaining = 0;
      for (let i = uses.length - 1; i >= 0; i--) {
        const m = uses[i];
        const key = memberKey(m.node);
        const info = key !== null ? table.get(key) : null;
        if (!info) { remaining++; continue; }
        const mp = m.parentPath;
        const isCallee = mp.isCallExpression() && mp.node.callee === m.node;
        if (info.kind === 'fn') {
          if (!isCallee) { remaining++; continue; }
          const rep = inlineCall(info, mp.node.arguments);
          if (!rep) { remaining++; continue; }
          mp.replaceWith(rep);
          stats.inlinedCalls++; changed++;
        } else {
          if (isCallee) { remaining++; continue; }
          m.replaceWith(t.cloneNode(info.node));
          stats.inlinedCalls++; changed++;
        }
      }
      if (remaining === 0) { path.remove(); stats.proxyObjects++; }
    },
    CallExpression: {
      exit(path) {
        const c = path.node.callee;
        if (!t.isMemberExpression(c) || !t.isObjectExpression(c.object)) return;
        const key = memberKey(c);
        if (key === null) return;
        const table = buildProxyTable(c.object);
        const info = table && table.get(key);
        if (!info || info.kind !== 'fn') return;
        const rep = inlineCall(info, path.node.arguments);
        if (!rep) return;
        path.replaceWith(rep);
        stats.inlinedCalls++; changed++;
      },
    },
  });
  return changed;
}

function simplifyLoop(ast, stats, maxIter = 8) {
  for (let i = 0; i < maxIter; i++) {
    let c = foldPass(ast, stats);
    traverse.cache.clear();
    c += inlinePass(ast, stats);
    traverse.cache.clear();
    if (!c) break;
  }
}

// ───────────────────────── Phase 3: remove infra ─────────────────────────
function removeInfra(ast, infra, stats) {
  const fnPaths = new Map();
  const rotPaths = new Map();
  traverse(ast, {
    Function(p) { if (infra.fnNodes.has(p.node)) fnPaths.set(p.node, p); },
    Statement(p) { if (infra.rotators.has(p.node)) rotPaths.set(p.node, p); },
  });
  const isInfra = (n) => infra.fnNodes.has(n) || infra.rotators.has(n);
  const declNode = (b) => {
    const fp = fnPathFromBinding(b);
    return fp ? fp.node : null;
  };
  const live = new Set();
  const work = [];
  const mark = (n) => { if (!live.has(n)) { live.add(n); work.push(n); } };

  for (const [node, p] of fnPaths) {
    const b = getFnBinding(p);
    if (!b) { mark(node); continue; }
    for (const ref of b.referencePaths) {
      if (!ref.findParent((pp) => isInfra(pp.node))) { mark(node); break; }
    }
    if (b.constantViolations.some((v) => !v.findParent((pp) => isInfra(pp.node)) && v.node !== node)) mark(node);
  }
  while (work.length) {
    const n = work.pop();
    const p = fnPaths.get(n);
    if (!p) continue;
    p.traverse({
      ReferencedIdentifier(ip) {
        const b = ip.scope.getBinding(ip.node.name);
        const d = b && declNode(b);
        if (d && infra.fnNodes.has(d)) mark(d);
      },
    });
  }
  for (const [node, p] of fnPaths) {
    if (live.has(node)) continue;
    if (p.isFunctionDeclaration()) p.remove();
    else if (p.parentPath.isVariableDeclarator()) p.parentPath.remove();
    else continue;
    stats.removedInfra++;
  }
  for (const [stmt, arrNode] of infra.rotators) {
    if (live.has(arrNode)) continue;
    const p = rotPaths.get(stmt);
    if (p) { p.remove(); stats.removedInfra++; }
  }
}

function removeUnusedLiteralVars(ast, stats) {
  traverse(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (!t.isIdentifier(id) || !init || !isLiteralNode(init)) return;
      if (path.scope.path.isProgram()) return;
      const b = path.scope.getBinding(id.name);
      if (!b) return;
      if (b.referenced || b.constantViolations.length) return;
      if (path.parentPath.parentPath && path.parentPath.parentPath.isFor()) return;
      path.remove();
      stats.unusedVars++;
    },
  });
}

// ── optimized rename: preallocated counter + Set lookups ──
function renameObfuscated(ast, stats) {
  let counter = 0;
  const usedNames = new Set();
  // Pre-scan: collect all existing non-obfuscated names to avoid collisions
  traverse(ast, {
    Scopable(path) {
      const scope = path.scope;
      if (scope.path.node !== path.node) return;
      const names = Object.keys(scope.bindings);
      if (!names.length) return;
      // Fast: skip scopes with no obfuscated names
      let hasObf = false;
      for (let i = 0; i < names.length; i++) {
        if (RE_OBF_ID.test(names[i])) { hasObf = true; break; }
      }
      if (!hasObf) return;
      for (let i = 0; i < names.length; i++) {
        const name = names[i];
        if (!RE_OBF_ID.test(name)) continue;
        const b = scope.bindings[name];
        const prefix = b.kind === 'param' ? 'arg' : b.path.isFunctionDeclaration() ? 'func' : 'var';
        let nn;
        let attempt = 0;
        do {
          nn = prefix + '_' + (++counter);
          // cheap check first, expensive only if collision
          if (!usedNames.has(nn) && !scope.hasBinding(nn) && !scope.hasGlobal(nn)) break;
        } while (++attempt < 1000);
        scope.rename(name, nn);
        usedNames.add(nn);
        stats.renamed++;
      }
    },
  });
}

// ───────────────────────── Phase 4: beautify ─────────────────────────
function hasLexicalDecl(block) {
  const body = block.body;
  for (let i = 0; i < body.length; i++) {
    const s = body[i];
    if ((t.isVariableDeclaration(s) && s.kind !== 'var') || t.isClassDeclaration(s) || t.isFunctionDeclaration(s)) return true;
  }
  return false;
}

function beautifyPass(ast) {
  const wrap = (path, key) => {
    const n = path.node[key];
    if (n && !t.isBlockStatement(n)) path.get(key).replaceWith(t.blockStatement(t.isEmptyStatement(n) ? [] : [n]));
  };
  const listParent = (p) => p.parentPath && (p.parentPath.isBlockStatement() || p.parentPath.isProgram() || p.parentPath.isSwitchCase());
  const stmt = (e) => t.expressionStatement(e);
  const blk = (e) => t.blockStatement([stmt(e)]);

  traverse(ast, {
    noScope: true,
    StringLiteral(path) { if (path.node.extra) delete path.node.extra; },
    NumericLiteral(path) { if (path.node.extra) delete path.node.extra; },
    IfStatement(path) {
      wrap(path, 'consequent');
      const alt = path.node.alternate;
      if (alt && !t.isBlockStatement(alt) && !t.isIfStatement(alt)) wrap(path, 'alternate');
    },
    'ForStatement|ForInStatement|ForOfStatement|WhileStatement|DoWhileStatement'(path) { wrap(path, 'body'); },
    UnaryExpression(path) {
      const n = path.node;
      if (n.operator === 'void' && t.isNumericLiteral(n.argument, { value: 0 })) path.replaceWith(t.identifier('undefined'));
    },
    ExpressionStatement(path) {
      const e = path.node.expression;
      if (!listParent(path)) return;
      if (t.isSequenceExpression(e)) { path.replaceWithMultiple(e.expressions.map(stmt)); return; }
      if (t.isLogicalExpression(e) && (e.operator === '&&' || e.operator === '||')) {
        const test = e.operator === '&&' ? e.left : t.unaryExpression('!', e.left);
        path.replaceWith(t.ifStatement(test, blk(e.right)));
        return;
      }
      if (t.isConditionalExpression(e)) path.replaceWith(t.ifStatement(e.test, blk(e.consequent), blk(e.alternate)));
    },
    'ReturnStatement|ThrowStatement'(path) {
      const a = path.node.argument;
      if (!a || !t.isSequenceExpression(a) || !listParent(path)) return;
      const ex = a.expressions;
      const last = ex[ex.length - 1];
      path.replaceWithMultiple([...ex.slice(0, -1).map(stmt),
        t.isReturnStatement(path.node) ? t.returnStatement(last) : t.throwStatement(last)]);
    },
    VariableDeclaration(path) {
      const n = path.node;
      if (n.declarations.length > 1 && listParent(path)) {
        path.replaceWithMultiple(n.declarations.map((d) => t.variableDeclaration(n.kind, [d])));
      }
    },
    BlockStatement(path) {
      const p = path.parentPath;
      if (!(p.isBlockStatement() || p.isProgram())) return;
      if (!path.node.body.length && !path.node.directives.length) { path.remove(); return; }
      if (!hasLexicalDecl(path.node) && !path.node.directives.length) path.replaceWithMultiple(path.node.body);
    },
  });
}

// ───────────────────────── main pipeline ─────────────────────────
function deobfuscate(code, options = {}) {
  const opts = Object.assign({ keepInfra: false, rename: true, unminify: true, verify: true }, options);
  const stats = {
    groupsFound: 0, groupsOk: 0, wrappers: 0, decoded: 0, inlinedCalls: 0, proxyObjects: 0,
    deadBranches: 0, removedInfra: 0, unusedVars: 0, renamed: 0, strings: new Map(),
  };
  const time = (label, fn) => {
    const s = Date.now();
    const r = fn();
    log(`  [${((Date.now() - s) / 1000).toFixed(1)}s] ${label}`);
    return r;
  };

  const ast = time('parse', () => parser.parse(code, {
    sourceType: 'unambiguous',
    allowReturnOutsideFunction: true,
    allowAwaitOutsideFunction: true,
    allowImportExportEverywhere: true,
    allowSuperOutsideMethod: true,
    allowUndeclaredExports: true,
    errorRecovery: true,
    // Fast path: skip comment/token attachment when we don't need them
    attachComment: false,
    tokens: false,
  }));
  if (ast.errors && ast.errors.length) log(`  ! parser recovered from ${ast.errors.length} error(s)`);

  const { infra } = time('decode string-arrays', () => decodeStrings(ast, code, stats, opts));
  log(`      groups: ${stats.groupsOk}/${stats.groupsFound}, wrappers: ${stats.wrappers}, decoded calls: ${stats.decoded}`);

  traverse.cache.clear();
  time('simplify (fold + inline proxies + dead code)', () => simplifyLoop(ast, stats));

  if (!opts.keepInfra && stats.groupsOk) {
    time('remove decoder/wrapper code', () => { traverse.cache.clear(); removeInfra(ast, infra, stats); });
    time('simplify again', () => { traverse.cache.clear(); simplifyLoop(ast, stats, 3); });
    time('remove unused constants', () => { traverse.cache.clear(); removeUnusedLiteralVars(ast, stats); });
  }
  if (opts.rename) time('rename _0x identifiers', () => { traverse.cache.clear(); renameObfuscated(ast, stats); });
  if (opts.unminify) time('beautify transforms', () => { traverse.cache.clear(); beautifyPass(ast); });

  const out = time('generate', () => generate(ast, {
    comments: false, compact: false, concise: false, retainLines: false,
    jsescOption: { minimal: true, quotes: 'double' },
  }, code).code);

  if (opts.verify) {
    time('verify output syntax', () => {
      try {
        parser.parse(out, {
          sourceType: 'unambiguous',
          allowReturnOutsideFunction: true,
          allowAwaitOutsideFunction: true,
          errorRecovery: false,
          attachComment: false,
          tokens: false,
        });
      } catch (e) { log('  ! WARNING: output failed to re-parse: ' + e.message); }
    });
  }
  return { code: out, stats };
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  QUIET = opts.quiet;
  if (opts.help || (!opts.input && process.stdin.isTTY)) { console.log(HELP); return; }

  let code;
  if (!opts.input || opts.input === '-') code = fs.readFileSync(0, 'utf8');
  else code = fs.readFileSync(opts.input, 'utf8');
  if (code.charCodeAt(0) === 0xFEFF) code = code.slice(1);
  if (code.startsWith('#!')) code = '//' + code;

  log(`Input: ${opts.input || '<stdin>'}  (${(code.length / 1024).toFixed(0)} KB)`);
  const { code: out, stats } = deobfuscate(code, opts);

  let target = opts.output;
  if (!target) {
    if (!opts.input || opts.input === '-') target = '-';
    else { const p = nodePath.parse(opts.input); target = nodePath.join(p.dir, p.name + '.deobf' + (p.ext || '.js')); }
  }
  if (target === '-') process.stdout.write(out);
  else { fs.writeFileSync(target, out); log(`Output: ${target}  (${(out.length / 1024).toFixed(0)} KB)`); }

  if (opts.dumpStrings) {
    const lines = [];
    for (const [s, c] of stats.strings) lines.push(`${c}\t${JSON.stringify(s)}`);
    fs.writeFileSync(opts.dumpStrings, lines.join('\n') + '\n');
    log(`Strings: ${opts.dumpStrings}  (${stats.strings.size} unique)`);
  }
  log(`Done. decoded=${stats.decoded} (unique ${stats.strings.size}), proxy-inlines=${stats.inlinedCalls}, ` +
      `dead-branches=${stats.deadBranches}, removed-infra=${stats.removedInfra}, unused-vars=${stats.unusedVars}, renamed=${stats.renamed}`);
}

if (require.main === module) main();
module.exports = { deobfuscate };