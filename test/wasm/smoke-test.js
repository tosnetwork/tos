// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//
// Loads the WebAssembly builds under Node.js and checks that they work:
//
//   node test/wasm/smoke-test.js <output dir> <commit>
//
// - funcfiftlib reports the commit it was built from, compiles a contract to a
//   code cell, and rejects a source with a syntax error (the negative control:
//   a compiler that answered "ok" to everything would pass the first check);
// - the emulator reports the same commit.
'use strict';

const path = require('path');

function fail(message) {
  console.error(`wasm smoke test: ${message}`);
  process.exit(1);
}

async function main() {
  const [dir, commit] = process.argv.slice(2);
  if (!dir || !/^[0-9a-f]{40}$/.test(commit || '')) {
    fail('usage: smoke-test.js <output dir> <40-character commit>');
  }

  const CompilerModule = require(path.resolve(dir, 'funcfiftlib.js'));
  const compiler = await CompilerModule();
  const version = JSON.parse(compiler.UTF8ToString(compiler._version()));
  if (version.funcFiftLibCommitHash !== commit) {
    fail(`funcfiftlib reports commit ${version.funcFiftLibCommitHash}, not ${commit}`);
  }

  // The compiler keeps its state in globals and is not reset between runs, so
  // each compilation gets its own instance of the module.
  async function compile(source) {
    const compiler = await CompilerModule();
    compiler.FS.writeFile('/main.fc', source);
    const config = JSON.stringify({ optLevel: 2, sources: ['/main.fc'] });
    const configPtr = compiler._malloc(compiler.lengthBytesUTF8(config) + 1);
    compiler.stringToUTF8(config, configPtr, compiler.lengthBytesUTF8(config) + 1);
    const resultPtr = compiler._func_compile(configPtr, 0);
    compiler._free(configPtr);
    const result = JSON.parse(compiler.UTF8ToString(resultPtr));
    compiler._free(resultPtr);
    return result;
  }

  const good = await compile('() recv_internal() impure {\n}\n');
  if (good.status !== 'ok' || typeof good.codeBoc !== 'string' || good.codeBoc.length === 0) {
    fail(`a valid contract did not compile: ${JSON.stringify(good)}`);
  }
  if (!/^[0-9A-Fa-f]{64}$/.test(good.codeHashHex || '')) {
    fail(`the compiled code has no 256-bit hash: ${good.codeHashHex}`);
  }
  const bad = await compile('() recv_internal() impure {\n');
  if (bad.status !== 'error') {
    fail(`a contract with a syntax error was accepted: ${JSON.stringify(bad)}`);
  }

  const EmulatorModule = require(path.resolve(dir, 'emulator-emscripten.js'));
  const emulator = await EmulatorModule();
  const emulatorVersion = JSON.parse(emulator.UTF8ToString(emulator._version()));
  if (emulatorVersion.emulatorLibCommitHash !== commit) {
    fail(`the emulator reports ${JSON.stringify(emulatorVersion)}, not commit ${commit}`);
  }

  console.log(`wasm smoke test: passed (code hash ${good.codeHashHex}, commit ${commit})`);
}

main().catch((error) => fail(error && error.stack ? error.stack : String(error)));
