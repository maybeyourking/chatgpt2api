#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const vm = require("node:vm");
const { performance } = require("node:perf_hooks");
const { createHash, webcrypto } = require("node:crypto");

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const JS_RESERVED_WORDS = new Set([
  "await", "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete",
  "do", "else", "enum", "export", "extends", "false", "finally", "for", "function", "if", "import",
  "in", "instanceof", "let", "new", "null", "return", "static", "super", "switch", "this", "throw",
  "true", "try", "typeof", "undefined", "var", "void", "while", "with", "yield",
]);

function sourceFingerprint(source) {
  return createHash("sha256").update(source).digest("hex").slice(0, 16);
}

function collectScopeCandidates(source, endOffset) {
  const names = new Set();
  const identifierPattern = /[$A-Z_a-z][$\w]*/g;
  const prefix = source.slice(0, endOffset);
  let match;
  while ((match = identifierPattern.exec(prefix)) !== null) {
    const name = match[0];
    if (!JS_RESERVED_WORDS.has(name)) {
      names.add(name);
    }
  }
  return [...names];
}

function buildScopeCapture(names, fingerprint) {
  const accumulator = `__sentinelScope_${fingerprint}`;
  const captures = names.map(
    (name) => `try{${accumulator}[${JSON.stringify(name)}]=${name}}catch{}`
  );
  return `(()=>{const ${accumulator}=Object.create(null);${captures.join("")}return ${accumulator}})()`;
}

function findExportAssignment(source) {
  const pattern = /([$A-Z_a-z][$\w]*)\.sessionObserverToken\s*=/g;
  let found = null;
  let match;
  while ((match = pattern.exec(source)) !== null) {
    found = {
      index: match.index,
      target: match[1],
      text: match[0],
    };
  }
  return found;
}

function patchSdkSource(source) {
  const fingerprint = sourceFingerprint(source);
  const legacyMarker = "t.init=we,t.sessionObserverToken=async function(t){";
  if (source.includes(legacyMarker)) {
    return {
      fingerprint,
      source: source.replace(
        legacyMarker,
        't.__internals={P:P,D:D,Et:Et,Nt:Nt,_n:_n,ce:ce};t.init=we,t.sessionObserverToken=async function(t){'
      ),
    };
  }

  const exportAssignment = findExportAssignment(source);
  if (!exportAssignment) {
    throw new Error(`unsupported_sdk_layout export_anchor_missing fingerprint=${fingerprint}`);
  }

  const scopeNames = collectScopeCandidates(source, exportAssignment.index);
  const scopeCapture = buildScopeCapture(scopeNames, fingerprint);
  const replacement = `${exportAssignment.target}.__scope=${scopeCapture},${exportAssignment.text}`;
  return {
    fingerprint,
    source: source.slice(0, exportAssignment.index) + replacement + source.slice(exportAssignment.index + exportAssignment.text.length),
  };
}

function functionSource(value) {
  if (typeof value !== "function") {
    return "";
  }
  try {
    return Function.prototype.toString.call(value);
  } catch {
    return "";
  }
}

function describeSdkLayout(sdk, fingerprint) {
  const scope = sdk?.__scope && typeof sdk.__scope === "object" ? sdk.__scope : {};
  const callableNames = Object.entries(scope)
    .filter(([, value]) => typeof value === "function")
    .map(([name]) => name)
    .slice(0, 80);
  return `fingerprint=${fingerprint} scope=${Object.keys(scope).length} callables=${callableNames.join(",") || "none"}`;
}

function findProvider(scope) {
  for (const value of Object.values(scope)) {
    if (
      value &&
      typeof value.getRequirementsToken === "function" &&
      typeof value.getEnforcementToken === "function"
    ) {
      return value;
    }
  }
  return null;
}

const KNOWN_SDK_LAYOUTS = {
  "49d0284bf3eea8a5": {
    provider: "E",
    setRequirements: "D",
    startObserver: "Mt",
    snapshot: "qt",
    turnstile: "Rn",
    serializer: "me",
  },
};

function resolveKnownInternals(scope, fingerprint) {
  const layout = KNOWN_SDK_LAYOUTS[fingerprint];
  if (!layout) {
    return null;
  }
  const resolved = {
    P: scope[layout.provider],
    D: scope[layout.setRequirements],
    Et: scope[layout.startObserver],
    Nt: scope[layout.snapshot],
    _n: scope[layout.turnstile],
    ce: scope[layout.serializer],
  };
  const providerValid =
    resolved.P &&
    typeof resolved.P.getRequirementsToken === "function" &&
    typeof resolved.P.getEnforcementToken === "function";
  const missing = Object.entries(resolved)
    .filter(([name, value]) => (name === "P" ? !providerValid : typeof value !== "function"))
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`known_sdk_layout_invalid missing=${missing.join(",")} fingerprint=${fingerprint}`);
  }
  return resolved;
}

function callExpressionAt(source, nameOffset) {
  const openParen = source.indexOf("(", nameOffset);
  if (openParen < 0) {
    return "";
  }
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = openParen; index < source.length; index += 1) {
    const char = source[index];
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = "";
      }
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      quote = char;
    } else if (char === "(") {
      depth += 1;
    } else if (char === ")") {
      depth -= 1;
      if (depth === 0) {
        return source.slice(nameOffset, index + 1);
      }
    }
  }
  return "";
}

function scopeFunctionCalls(scope, fn) {
  const source = functionSource(fn);
  const calls = [];
  for (const [name, value] of Object.entries(scope)) {
    if (typeof value !== "function") {
      continue;
    }
    const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pattern = new RegExp(`(?:^|[^.$\\w])${escapedName}\\s*\\(`, "g");
    let match;
    while ((match = pattern.exec(source)) !== null) {
      const callOffset = match.index + match[0].lastIndexOf(name);
      calls.push({
        name,
        value,
        offset: callOffset,
        expression: callExpressionAt(source, callOffset).toLowerCase(),
      });
    }
  }
  return calls.sort((left, right) => left.offset - right.offset);
}

function findCallByFragments(calls, fragments, excluded = new Set()) {
  const matches = calls.filter(
    (call) =>
      !excluded.has(call.value) &&
      fragments.every((fragment) => call.expression.includes(fragment.toLowerCase()))
  );
  const values = [...new Set(matches.map((call) => call.value))];
  return values.length === 1 ? values[0] : null;
}

function resolveInternals(sdk, fingerprint) {
  const direct = sdk?.__internals || sdk;
  if (
    direct &&
    direct.P &&
    typeof direct.D === "function" &&
    typeof direct.Et === "function" &&
    typeof direct.Nt === "function" &&
    typeof direct._n === "function" &&
    typeof direct.ce === "function"
  ) {
    return direct;
  }

  const scope = sdk?.__scope && typeof sdk.__scope === "object" ? sdk.__scope : {};
  const known = resolveKnownInternals(scope, fingerprint);
  if (known) {
    return known;
  }
  const provider = findProvider(scope);
  const used = new Set();
  if (provider) {
    used.add(provider);
  }

  const observerCalls = scopeFunctionCalls(scope, sdk?.sessionObserverToken);

  const turnstile = findCallByFragments(observerCalls, ["turnstile", "dx"], used);
  if (turnstile) used.add(turnstile);
  const snapshot = findCallByFragments(observerCalls, ["snapshot_dx"], used);
  if (snapshot) used.add(snapshot);
  const serializer = findCallByFragments(observerCalls, ["{", "p:", "t:", "c:"], used);
  if (serializer) used.add(serializer);

  const remainingCalls = observerCalls.filter((call) => !used.has(call.value));
  const twoArgumentCalls = [...new Set(remainingCalls.filter((call) => call.value.length >= 2).map((call) => call.value))];
  const oneArgumentCalls = [...new Set(remainingCalls.filter((call) => call.value.length <= 1).map((call) => call.value))];
  const setRequirements = twoArgumentCalls.length === 1 ? twoArgumentCalls[0] : null;
  if (setRequirements) used.add(setRequirements);
  const startObserver = oneArgumentCalls.length === 1 ? oneArgumentCalls[0] : null;

  const resolved = {
    P: provider,
    D: setRequirements,
    Et: startObserver,
    Nt: snapshot,
    _n: turnstile,
    ce: serializer,
  };
  const missing = Object.entries(resolved)
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(
      `unsupported_sdk_layout missing=${missing.join(",")} ${describeSdkLayout(sdk, fingerprint)}`
    );
  }
  return resolved;
}

function createSandbox({ sdkUrl, deviceId }) {
  const sandbox = {};
  const scripts = [{ src: sdkUrl }];
  const document = {
    scripts,
    currentScript: scripts[0],
    body: { appendChild() {} },
    head: { appendChild() {} },
    documentElement: { getAttribute() { return ""; } },
    createElement() {
      return {
        style: {},
        addEventListener() {},
        contentWindow: { postMessage() {} },
      };
    },
    cookie: deviceId ? `oai-did=${encodeURIComponent(deviceId)}` : "",
  };
  const navigator = {
    userAgent:
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
    language: "en-US",
    languages: ["en-US", "en"],
    hardwareConcurrency: 8,
  };
  const location = new URL("https://sentinel.openai.com/backend-api/sentinel/frame.html");
  const window = {
    document,
    navigator,
    location,
    top: {},
    addEventListener() {},
    removeEventListener() {},
    requestIdleCallback(cb) {
      return setTimeout(() => cb({ timeRemaining: () => 10, didTimeout: false }), 0);
    },
    setTimeout,
    clearTimeout,
    performance,
    crypto: webcrypto,
    atob: (value) => Buffer.from(value, "base64").toString("binary"),
    btoa: (value) => Buffer.from(value, "binary").toString("base64"),
  };
  window.window = window;
  window.self = window;
  sandbox.window = window;
  sandbox.self = window;
  sandbox.globalThis = window;
  sandbox.document = document;
  sandbox.navigator = navigator;
  sandbox.location = location;
  sandbox.performance = performance;
  sandbox.screen = { width: 1920, height: 1080 };
  sandbox.crypto = webcrypto;
  sandbox.URL = URL;
  sandbox.URLSearchParams = URLSearchParams;
  sandbox.TextEncoder = TextEncoder;
  sandbox.TextDecoder = TextDecoder;
  sandbox.fetch = async () => {
    throw new Error("fetch_not_supported_in_helper");
  };
  sandbox.setTimeout = setTimeout;
  sandbox.clearTimeout = clearTimeout;
  sandbox.atob = window.atob;
  sandbox.btoa = window.btoa;
  sandbox.console = console;
  return sandbox;
}

async function main() {
  const raw = fs.readFileSync(0, "utf8");
  const payload = JSON.parse(raw || "{}");
  const patched = patchSdkSource(fs.readFileSync(payload.sdkPath, "utf8"));
  const sandbox = createSandbox({ sdkUrl: payload.sdkUrl, deviceId: payload.deviceId });
  vm.createContext(sandbox);
  vm.runInContext(patched.source, sandbox, { filename: "openai-sentinel-sdk.js" });
  const sdk = sandbox.SentinelSDK || sandbox.window?.SentinelSDK;
  if (!sdk) {
    fail("sdk_internals_missing");
  }
  const internals = resolveInternals(sdk, patched.fingerprint);

  if (payload.mode === "requirements") {
    const requirementsToken = await internals.P.getRequirementsToken();
    process.stdout.write(
      JSON.stringify({
        sdkVersion: payload.sdkVersion,
        requirementsToken,
      })
    );
    return;
  }

  if (payload.mode !== "enforcement") {
    fail("unsupported_mode");
  }

  const chatReq = payload.chatReq;
  const requirementsToken = String(payload.requirementsToken || "");
  const flow = String(payload.flow || "");
  if (!chatReq || !requirementsToken || !flow) {
    fail("missing_enforcement_payload");
  }

  internals.D(chatReq, requirementsToken);
  internals.Et(chatReq);
  await sleep(Math.max(5000, Number(payload.soWaitMs || 5000)));

  const proofToken = await internals.P.getEnforcementToken(chatReq);
  const turnstileToken = chatReq?.turnstile?.dx ? await internals._n(chatReq, chatReq.turnstile.dx) : null;
  const sentinelToken = internals.ce(
    {
      p: proofToken,
      t: turnstileToken,
      c: chatReq.token,
    },
    flow
  );

  let soToken = null;
  if (chatReq?.so?.required === true && typeof chatReq?.so?.snapshot_dx === "string") {
    const soValue = await internals.Nt(chatReq.so.snapshot_dx);
    soToken = chatReq.token ? internals.ce({ so: soValue, c: chatReq.token }, flow) : soValue;
  }

  process.stdout.write(
    JSON.stringify({
      sdkVersion: payload.sdkVersion,
      sentinelToken,
      proofToken,
      turnstileToken,
      soToken,
    })
  );
}

if (require.main === module) {
  main().catch((error) => fail(error && error.stack ? error.stack : String(error)));
}

module.exports = {
  findExportAssignment,
  patchSdkSource,
  resolveInternals,
  resolveKnownInternals,
  scopeFunctionCalls,
  sourceFingerprint,
};
