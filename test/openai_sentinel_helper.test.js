"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const vm = require("node:vm");

const {
  patchSdkSource,
  resolveInternals,
  resolveKnownInternals,
} = require("../services/register/openai_sentinel_helper.js");

function evaluateFixture(source) {
  const patched = patchSdkSource(source);
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(patched.source, sandbox);
  return {
    fingerprint: patched.fingerprint,
    sdk: sandbox.SentinelSDK,
  };
}

test("keeps the known legacy SDK layout on its exact compatibility path", () => {
  const source = `(()=>{const P={getRequirementsToken(){},getEnforcementToken(){}};
    function D(){}function Et(){}function Nt(){}function _n(){}function ce(){}function we(){}
    const t={};t.init=we,t.sessionObserverToken=async function(t){};
    globalThis.SentinelSDK=t})()`;
  const { sdk, fingerprint } = evaluateFixture(source);
  const internals = resolveInternals(sdk, fingerprint);

  assert.equal(internals.P, sdk.__internals.P);
  assert.equal(internals.D, sdk.__internals.D);
  assert.equal(internals.ce, sdk.__internals.ce);
});

test("patches renamed minified export bindings", () => {
  const source = `(()=>{const aa={getRequirementsToken(){},getEnforcementToken(){}};
    function bb(value,token){return value&&token}function cc(value){return value}
    function dd(value){return value.snapshot_dx}function ee(value){return value.turnstile.dx}
    function ff(value,flow){return JSON.stringify({value,flow})}
    function gg(){}const out={};out.init=gg,out.sessionObserverToken=async function(){};
    globalThis.SentinelSDK=out})()`;
  const { sdk } = evaluateFixture(source);

  assert.equal(typeof sdk.__scope.aa.getRequirementsToken, "function");
  assert.equal(typeof sdk.__scope.gg, "function");
});

test("patches SDK when public exports are separated or reordered", () => {
  const source = `(()=>{function zz(){}const api={};
    api.sessionObserverToken=async value=>value;api.init=zz;
    globalThis.SentinelSDK=api})()`;
  const { sdk } = evaluateFixture(source);

  assert.equal(typeof sdk.__scope.zz, "function");
  assert.equal(typeof sdk.sessionObserverToken, "function");
});

test("resolves SDK roles by capabilities instead of minified names", () => {
  const source = `(()=>{const aa={getRequirementsToken(){},getEnforcementToken(){}};
    function bb(a,b){return a&&b}function cc(a){return a}
    function dd(a){return a}function ee(a,b){return a&&b}
    function ff(a,b){return JSON.stringify([a,b])}
    function gg(){}const out={};out.init=gg,out.sessionObserverToken=async function(a){
      const b=a.chatReq;bb(b,a.requirementsToken);cc(b);
      const p=await aa.getEnforcementToken(b);
      const t=b.turnstile&&b.turnstile.dx?await ee(b,b.turnstile.dx):null;
      const token=ff({p:p,t:t,c:b.token},a.flow);
      const so=b.so&&b.so.snapshot_dx?await dd(b.so.snapshot_dx):null;
      return {token,so}
    };
    globalThis.SentinelSDK=out})()`;
  const { sdk, fingerprint } = evaluateFixture(source);
  const internals = resolveInternals(sdk, fingerprint);

  assert.equal(internals.P, sdk.__scope.aa);
  assert.equal(internals.D, sdk.__scope.bb);
  assert.equal(internals.Et, sdk.__scope.cc);
  assert.equal(internals.Nt, sdk.__scope.dd);
  assert.equal(internals._n, sdk.__scope.ee);
  assert.equal(internals.ce, sdk.__scope.ff);
});

test("resolves the deployed 20260810913b SDK layout by verified fingerprint", () => {
  const provider = { getRequirementsToken() {}, getEnforcementToken() {} };
  const scope = {
    E: provider,
    D() {},
    Mt() {},
    qt() {},
    Rn() {},
    me() {},
  };

  const internals = resolveKnownInternals(scope, "49d0284bf3eea8a5");

  assert.equal(internals.P, provider);
  assert.equal(internals.D, scope.D);
  assert.equal(internals.Et, scope.Mt);
  assert.equal(internals.Nt, scope.qt);
  assert.equal(internals._n, scope.Rn);
  assert.equal(internals.ce, scope.me);
});

test("rejects a known fingerprint when its expected capabilities changed", () => {
  assert.throws(
    () => resolveKnownInternals({ E: {} }, "49d0284bf3eea8a5"),
    /known_sdk_layout_invalid missing=/
  );
});

test("reports a source fingerprint when the export layout is unsupported", () => {
  assert.throws(
    () => patchSdkSource("globalThis.SentinelSDK={init(){}}"),
    /export_anchor_missing fingerprint=[a-f0-9]{16}/
  );
});

test("reports missing SDK roles without guessing a token implementation", () => {
  const source = `(()=>{function init(){}const out={};out.init=init,out.sessionObserverToken=async function(){};
    globalThis.SentinelSDK=out})()`;
  const { sdk, fingerprint } = evaluateFixture(source);

  assert.throws(
    () => resolveInternals(sdk, fingerprint),
    new RegExp(`unsupported_sdk_layout missing=.*fingerprint=${fingerprint}`)
  );
});

test("helper executes renamed SDK implementations end to end", () => {
  const sdkSource = `(()=>{const provider={
      getRequirementsToken(){return "requirements-from-sdk"},
      getEnforcementToken(req){return "proof-"+req.token}
    };
    function remember(a,b){globalThis.remembered=[a,b]}
    function observe(a){globalThis.observed=a}
    async function snapshot(a){return "snapshot-"+a}
    async function turnstile(a,b){return "turnstile-"+b}
    function serialize(a,b){return "sentinel-"+JSON.stringify(a)+"-"+b}
    function init(){}const api={};api.init=init;api.sessionObserverToken=async function(a){
      const req=a.chatReq;remember(req,a.requirementsToken);observe(req);
      const proof=await provider.getEnforcementToken(req);
      const turn=req.turnstile&&req.turnstile.dx?await turnstile(req,req.turnstile.dx):null;
      const token=serialize({p:proof,t:turn,c:req.token},a.flow);
      const so=req.so&&req.so.snapshot_dx?await snapshot(req.so.snapshot_dx):null;
      return {token,so}
    };globalThis.SentinelSDK=api})()`;
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-helper-test-"));
  const sdkPath = path.join(tempDir, "sdk.js");
  fs.writeFileSync(sdkPath, sdkSource);
  try {
    const result = spawnSync(process.execPath, [path.join(__dirname, "../services/register/openai_sentinel_helper.js")], {
      encoding: "utf8",
      input: JSON.stringify({
        mode: "enforcement",
        sdkPath,
        sdkUrl: "https://sentinel.openai.com/sentinel/test/sdk.js",
        sdkVersion: "test",
        deviceId: "device-test",
        flow: "oauth_create_account",
        requirementsToken: "requirements-from-sdk",
        soWaitMs: 0,
        chatReq: {
          token: "request-token",
          turnstile: { dx: "turnstile-dx" },
          so: { required: true, snapshot_dx: "snapshot-dx" },
        },
      }),
    });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.proofToken, "proof-request-token");
    assert.equal(output.turnstileToken, "turnstile-turnstile-dx");
    assert.match(output.sentinelToken, /^sentinel-/);
    assert.match(output.soToken, /^sentinel-/);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
