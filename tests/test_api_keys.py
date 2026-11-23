import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from quickpool.main import create_app
from quickpool.store import Store
from tests.test_gateway import add

pytest_plugins = ['tests.test_gateway']


def create_key(client, admin, name='Codex 笔记本'):
    response = client.post('/api/keys', headers=admin, json={'name': name})
    assert response.status_code == 201, response.text
    return response.json()


def test_legacy_key_is_migrated_without_changing_files(tmp_path, monkeypatch):
    monkeypatch.delenv('QUICKPOOL_API_KEY', raising=False)
    default = 'sk-quick-existing-fixture-key-never-rotate'
    (tmp_path / 'api.key').write_text(default)
    # Simulate the old version's database: no api_keys table yet.
    with sqlite3.connect(tmp_path / 'quickpool.db') as db:
        db.execute('CREATE TABLE migration_fixture (value TEXT)')
        db.execute("INSERT INTO migration_fixture VALUES ('unchanged')")
    store = Store(tmp_path)
    assert store.api_key == default and store.authenticate_api_key(default)
    assert store.api_keys()[0]['id'] == 'default'
    created = store.create_api_key('extra')
    assert created['api_key'] != default
    assert store.revoke_api_key('default')
    store.close()
    store = Store(tmp_path)
    assert not store.authenticate_api_key(default)
    assert store.authenticate_api_key(created['api_key'])
    assert store.reveal_api_key(created['id']) == created['api_key']
    assert store.reveal_api_key('default') is None
    assert store.db.execute('SELECT value FROM migration_fixture').fetchone()[0] == 'unchanged'
    assert (tmp_path / 'api.key').read_text() == default
    store.close()


def test_environment_default_rotation_preserves_additional_keys(tmp_path, monkeypatch):
    monkeypatch.setenv('QUICKPOOL_API_KEY', 'fixture-env-original-key')
    store = Store(tmp_path)
    created = store.create_api_key('extra')
    store.revoke_api_key('default')
    store.close()
    monkeypatch.setenv('QUICKPOOL_API_KEY', 'fixture-env-replaced-key')
    store = Store(tmp_path)
    assert not store.authenticate_api_key('fixture-env-original-key')
    assert store.authenticate_api_key('fixture-env-replaced-key')
    assert store.authenticate_api_key(created['api_key'])
    assert store.reveal_api_key('default') == 'fixture-env-replaced-key'
    store.close()


def test_management_auth_masking_reveal_revoke_and_isolation(gateway):
    client, app, admin, legacy, _backend = gateway
    a = create_key(client, admin, '  Codex  ')
    b = create_key(client, admin, 'Claude')
    assert a['name'] == 'Codex' and a['id'] != b['id'] and a['api_key'] != b['api_key']
    headers = {'Authorization': 'Bearer ' + a['api_key']}
    for auth in ({}, headers, legacy):
        assert client.get('/api/keys', headers=auth).status_code == 401
        assert client.post('/api/keys', headers=auth, json={'name': 'denied'}).status_code == 401
        assert client.post(f'/api/keys/{a["id"]}/reveal', headers=auth).status_code == 401
        assert client.delete(f'/api/keys/{a["id"]}', headers=auth).status_code == 401
    assert client.get('/v1/models', headers=headers).status_code == 200
    listing = client.get('/api/keys', headers=admin)
    for secret in (a['api_key'], b['api_key'], app.state.store.api_key):
        assert secret not in listing.text
    assert 'key_hash' not in listing.text and 'secret' not in listing.text
    row = next(item for item in listing.json()['keys'] if item['id'] == a['id'])
    assert row['last_used'] > 0 and row['enabled'] and row['masked'] != a['api_key']
    assert client.post(f'/api/keys/{a["id"]}/reveal', headers=admin).json()['api_key'] == a['api_key']
    encrypted = app.state.store.db.execute('SELECT secret FROM api_keys WHERE id=?', (a['id'],)).fetchone()[0]
    assert a['api_key'].encode() not in encrypted
    assert app.state.store.cipher.decrypt(encrypted).decode() == a['api_key']
    for _ in range(2):
        assert client.delete(f'/api/keys/{a["id"]}', headers=admin).status_code == 204
    assert client.get('/v1/models', headers=headers).status_code == 401
    assert client.post(f'/api/keys/{a["id"]}/reveal', headers=admin).status_code == 404
    assert client.get('/v1/models', headers={'Authorization': 'Bearer ' + b['api_key']}).status_code == 200
    assert client.get('/v1/models', headers=legacy).status_code == 200
    assert client.delete('/api/keys/missing', headers=admin).status_code == 404
    assert client.post('/api/keys/missing/reveal', headers=admin).status_code == 404


@pytest.mark.parametrize('body', [{}, {'name': ''}, {'name': '  '}, {'name': 'a'*81},
                                  {'name': 123}, {'name': 'x', 'api_key': 'DO_NOT_ECHO'}])
def test_creation_validation_does_not_echo_payloads(gateway, body):
    client, _app, admin, _key, _backend = gateway
    response = client.post('/api/keys', headers=admin, json=body)
    assert response.status_code == 422
    assert 'DO_NOT_ECHO' not in response.text


@pytest.mark.parametrize('protocol', ['chat/completions', 'responses', 'messages'])
@pytest.mark.parametrize('stream', [False, True])
def test_additional_keys_work_for_all_protocols_and_streaming(gateway, protocol, stream):
    client, _app, admin, _key, _backend = gateway
    add(gateway, state='ready')
    a, b = create_key(client, admin, 'a'), create_key(client, admin, 'b')
    body = {'model': 'amazon-fast', 'stream': stream, 'max_tokens': 100}
    body.update({'input': 'Hello'} if protocol == 'responses' else
                {'messages': [{'role': 'user', 'content': 'Hello'}]})
    for item in (a, b):
        headers = ({'x-api-key': item['api_key']} if protocol == 'messages' else
                   {'Authorization': 'Bearer ' + item['api_key']})
        response = client.post('/v1/' + protocol, headers=headers, json=body)
        assert response.status_code == 200, response.text
        assert '你好' in response.text or '\\u4f60\\u597d' in response.text
        if stream:
            ending = {'chat/completions': '[DONE]', 'responses': 'response.completed',
                      'messages': 'message_stop'}[protocol]
            assert ending in response.text
    assert client.delete('/api/keys/' + a['id'], headers=admin).status_code == 204
    revoked = {'Authorization': 'Bearer ' + a['api_key']}
    assert client.post('/v1/' + protocol, headers=revoked, json=body).status_code == 401
    if protocol == 'messages':
        assert client.post('/messages', headers={'x-api-key': a['api_key']}, json=body).status_code == 401
        assert client.post('/v1/messages/count_tokens', headers={'x-api-key': b['api_key']},
                           json=body).status_code == 200


def test_restart_keeps_created_and_revoked_keys(tmp_path):
    app = create_app(tmp_path)
    with TestClient(app) as client:
        admin = {'Authorization': 'Bearer ' + app.state.store.admin_key}
        a, b = create_key(client, admin, 'persist'), create_key(client, admin, 'revoke')
        assert client.delete('/api/keys/' + b['id'], headers=admin).status_code == 204
        assert client.delete('/api/keys/default', headers=admin).status_code == 204
    with TestClient(create_app(tmp_path)) as client:
        assert client.get('/v1/models', headers={'Authorization': 'Bearer ' + a['api_key']}).status_code == 200
        assert client.get('/v1/models', headers={'Authorization': 'Bearer ' + b['api_key']}).status_code == 401
        assert client.post('/api/config/reveal-key', headers=admin).status_code == 404


def test_concurrent_creation_and_active_key_limit(tmp_path):
    store = Store(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as executor:
        created = list(executor.map(lambda index: store.create_api_key(str(index)), range(99)))
    assert len({key['api_key'] for key in created}) == 99
    with pytest.raises(ValueError, match='100'):
        store.create_api_key('too many')
    store.revoke_api_key(created[0]['id'])
    replacement = store.create_api_key('replacement')
    assert store.authenticate_api_key(replacement['api_key'])
    assert not store.authenticate_api_key('')
    assert not store.authenticate_api_key('x'*513)
    assert not store.authenticate_api_key("' OR 1=1 --")
    assert not store.authenticate_api_key(store.admin_key)
    assert 'api_key' not in json.dumps(store.api_keys())
    store.close()
