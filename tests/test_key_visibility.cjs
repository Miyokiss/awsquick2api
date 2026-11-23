// HTTP deployments can have no clipboard API, or the browser can reject access.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../quickpool/static/app.js'), 'utf8');
const helpers = source.slice(source.indexOf('function showCopyDialog('), source.indexOf('async function api('));

(async () => {
  for (const mode of ['missing', 'rejected', 'success']) {
    const nodes = new Map();
    const $ = selector => {
      if (!nodes.has(selector)) nodes.set(selector, {
        value: '', textContent: '', open: false, focused: false, selected: false,
        showModal() { this.open = true; }, close() { this.open = false; },
        focus() { this.focused = true; }, select() { this.selected = true; },
      });
      return nodes.get(selector);
    };
    let copied;
    const context = { $, state: {admin: 'fixture-admin'}, navigator: {},
      text: (selector, value) => { $(selector).textContent = value; }, toast: () => {},
    };
    if (mode !== 'missing') context.navigator.clipboard = {writeText: async value => {
      if (mode === 'rejected') throw Error('NotAllowedError');
      copied = value;
    }};
    vm.createContext(context);
    vm.runInContext(helpers, context);
    await context.copy('fixture-full-key', 'API Key · fixture');
    if (mode === 'success') {
      assert.equal(copied, 'fixture-full-key');
      assert.equal($('#copy-dialog').open, false);
    } else {
      assert.equal($('#copy-dialog').open, true);
      assert.equal($('#copy-value').value, 'fixture-full-key');
      assert.equal($('#copy-value').selected, true);
      assert.match($('#copy-dialog-status').textContent, /Ctrl\+C/);
      context.closeCopyDialog();
      assert.equal($('#copy-value').value, '');
      assert.equal($('#copy-dialog').open, false);
    }
    // An in-flight clipboard denial must not reopen a key after logout.
    let reject;
    context.navigator.clipboard = {writeText: () => new Promise((_, fail) => { reject = fail; })};
    const pending = context.copy('fixture-stale-key');
    context.state.admin = '';
    reject(Error('NotAllowedError'));
    await pending;
    assert.equal($('#copy-dialog').open, false);
    assert.equal($('#copy-value').value, '');
    console.log(JSON.stringify({clipboard: mode, manual_copy_and_logout: 'passed'}));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
