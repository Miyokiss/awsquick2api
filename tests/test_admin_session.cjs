// Upstream OAuth expiry must not log the administrator out of the panel.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../quickpool/static/app.js'), 'utf8');
const api = source.slice(source.indexOf('async function api('), source.indexOf('function showAuth('));

(async () => {
  for (const [detail, shouldLogout] of [
    ['原生授权已失效，需要重新授权', false], ['管理密钥无效', true],
  ]) {
    const context = {
      state: {admin: 'FIXTURE_ADMIN'},
      fetch: async () => ({status: 401, ok: false, json: async () => ({detail})}),
      sessionStorage: {removeItem: () => {}},
      stopAuthPolling: () => {}, $: () => ({open: false}), showAuth: () => {},
    };
    vm.createContext(context);
    vm.runInContext(api, context);
    await assert.rejects(context.api('/api/accounts/fixture/auth/refresh'));
    assert.equal(context.state.admin === '', shouldLogout);
    console.log(JSON.stringify({detail, admin_logged_out: shouldLogout, passed: true}));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
