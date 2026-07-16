#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const vm = require("node:vm");
const { performance } = require("node:perf_hooks");
const { webcrypto } = require("node:crypto");

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function patchSdkSource(source) {
  const marker = "t.init=we,t.sessionObserverToken=async function(t){";
  if (!source.includes(marker)) {
    throw new Error("unsupported_sdk_layout");
  }
  return source.replace(
    marker,
    't.__internals={P:P,D:D,Et:Et,Nt:Nt,_n:_n,ce:ce,qn:qn};t.init=we,t.sessionObserverToken=async function(t){'
  );
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
  const source = patchSdkSource(fs.readFileSync(payload.sdkPath, "utf8"));
  const sandbox = createSandbox({ sdkUrl: payload.sdkUrl, deviceId: payload.deviceId });
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: "openai-sentinel-sdk.js" });
  const sdk = sandbox.SentinelSDK || sandbox.window?.SentinelSDK;
  const internals = sdk && (sdk.__internals || sdk);
  if (!internals) {
    fail("sdk_internals_missing");
  }

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

main().catch((error) => fail(error && error.stack ? error.stack : String(error)));
