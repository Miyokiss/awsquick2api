import asyncio
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from quickpool.models import AccountCreate, NativeLoginRequest
from quickpool.native_auth import AuthError, Login, NativeAuth, trusted_url
from quickpool.store import Store


@pytest.fixture
def setup_auth(tmp_path):
    store = Store(tmp_path)
    account = store.create_account(AccountCreate(name='fixture', login_url='https://quick.aws.com/sn'))
    auth = NativeAuth(store, port=18080)
    yield auth, store, account['id']
    store.close()


def discovery_query(login):
    return {'nonce': login.nonce, 'issuerUrl': 'https://fixture.awsapps.com/start',
            'tenantUrl': 'https://fixture.quick.aws.com', 'idcRegion': 'us-east-1'}


async def test_social_pkce_idc_code_and_rotating_refresh(setup_auth):
    auth, store, account_id = setup_auth
    calls = []

    async def handle(request):
        calls.append(request)
        body = json.loads(request.content)
        if request.url.path == '/client/register':
            assert body == {'clientName': 'AmazonQuick-Desktop', 'clientType': 'public',
                            'scopes': ['quicksight:read_write'],
                            'grantTypes': ['authorization_code', 'refresh_token'],
                            'redirectUris': ['http://127.0.0.1:18080'],
                            'issuerUrl': 'https://fixture.awsapps.com/start'}
            return httpx.Response(200, json={'clientId': 'fixture', 'clientSecret': 'PRIVATE_CLIENT'})
        if request.url.path == '/token':
            assert body['clientId'] == 'fixture' and body['clientSecret'] == 'PRIVATE_CLIENT'
            if body['grantType'] == 'authorization_code':
                assert body['redirectUri'] == 'http://127.0.0.1:18080'
                assert body['code'] == 'PRIVATE_CODE' and len(body['codeVerifier']) >= 43
                token = 'PRIVATE_ACCESS'
            else:
                assert body['refreshToken'] == 'PRIVATE_REFRESH'
                token = 'PRIVATE_NEW_ACCESS'
            return httpx.Response(200, json={'accessToken': token, 'refreshToken': 'PRIVATE_REFRESH',
                                            'expiresIn': 3600})
        assert request.url.path == '/integration/quick-work/user-info'
        assert request.headers['Authorization'] == 'Bearer PRIVATE_ACCESS'
        return httpx.Response(200, json={'userInfo': {'awsAccountId': '000000000000'}})

    auth.transport = httpx.MockTransport(handle)
    login = Login(account_id, 'social', 'us-east-1')
    auth.logins[account_id] = login
    authorize = await auth.discovery(discovery_query(login))
    params = parse_qs(urlsplit(authorize).query)
    assert params['redirect_uri'] == ['http://127.0.0.1:18080']
    assert params['prompt'] == ['login']
    assert params['code_challenge'] == [login.challenge]
    state = login.state
    await auth.complete({'state': state, 'code': 'PRIVATE_CODE'})
    assert auth.status(account_id)['status'] == 'authorized'
    assert store.account(account_id)['state'] == 'unverified'
    assert store.account(account_id)['has_refresh_token']
    assert store.account(account_id)['aws_account_id'] == '000000000000'
    assert 'PRIVATE' not in json.dumps(store.account(account_id))
    assert not login.state and not login.nonce and not login.verifier
    with pytest.raises(AuthError):
        await auth.complete({'state': state, 'code': 'PRIVATE_CODE'})
    await auth.credentials(account_id, force=True)
    assert store.credentials(account_id)['access_token'] == 'PRIVATE_NEW_ACCESS'
    assert store.credentials(account_id)['refresh_token'] == 'PRIVATE_REFRESH'


async def test_discovery_replay_preserves_first_failure(setup_auth):
    auth, _, account_id = setup_auth
    auth.transport = httpx.MockTransport(lambda request: httpx.Response(
        400, json={'error': 'invalid_redirect_uri', 'error_description': 'PRIVATE_DETAIL'}))
    login = Login(account_id, 'social', 'us-east-1')
    auth.logins[account_id] = login
    query = discovery_query(login)
    for _ in range(2):
        with pytest.raises(AuthError, match='invalid_redirect_uri'):
            await auth.discovery(query)
    assert 'HTTP 400' in login.error and 'PRIVATE_DETAIL' not in login.error


async def test_concurrent_discovery_registers_once(setup_auth):
    auth, _, account_id = setup_auth
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return httpx.Response(200, json={'clientId': 'fixture', 'clientSecret': 'PRIVATE'})

    auth.transport = httpx.MockTransport(handler)
    login = Login(account_id, 'social', 'us-east-1')
    auth.logins[account_id] = login
    query = discovery_query(login)
    first = asyncio.create_task(auth.discovery(query))
    await entered.wait()
    with pytest.raises(AuthError) as error:
        await auth.discovery(query)
    assert error.value.status == 409 and login.status == 'discovering'
    release.set()
    await first
    assert calls == 1 and login.status == 'awaiting_authorization'


@pytest.mark.parametrize('url', ['https://evil.invalid', 'http://quick.aws.com',
    'https://quick.aws.com@evil.invalid', 'https://quick.aws.com:8443',
    'https://quick.aws.com/a\r\nLocation:bad', 'https://quick.aws.com/#bad',
    'https://quick.aws.com.evil.invalid', 'https:// quick.aws.com'])
def test_trusted_url_rejects_untrusted_and_header_injection(url):
    with pytest.raises(AuthError): trusted_url(url)


def test_missing_nonce_and_state_never_match_erased_values(setup_auth):
    auth, _, account_id = setup_auth
    auth.logins[account_id] = Login(account_id, 'social', 'us-east-1', nonce='', state='')
    for nonce in [True, False]:
        with pytest.raises(AuthError): auth._find('', nonce=nonce)
    assert NativeLoginRequest().provider == 'social'


def test_observed_quick_personal_dataplane_host():
    host = 'qbs-cell11111111-2222-4333-8444-555555555555.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev'
    assert trusted_url('https://'+host) == 'https://'+host
    for bad in [host+'.evil.invalid', 'evil.aws.dev', host.replace('.prod.', '.test.')]:
        with pytest.raises(AuthError): trusted_url('https://'+bad)


@pytest.mark.parametrize('status,body,expected', [
    (503, {'error': 'temporarily_unavailable'}, 503),
    (400, {'error': 'invalid_grant'}, 401),
])
async def test_refresh_failure_retains_refresh_token(setup_auth, status, body, expected):
    auth, store, account_id = setup_auth
    credentials = {'_kind': 'desktop-oauth', 'provider': 'gateway',
        'clientId': 'fixture', 'tokenEndpoint': 'https://auth.quick.aws.com/token',
        'tenantUrl': 'https://fixture.quick.aws.com', 'access_token': 'PRIVATE_OLD',
        'refresh_token': 'PRIVATE_REFRESH', 'expires_at': time.time()-1}
    store.set_credentials(account_id, credentials, state='ready')
    auth.transport = httpx.MockTransport(lambda request: httpx.Response(status,json=body))
    with pytest.raises(AuthError) as error:
        await auth.credentials(account_id)
    assert error.value.status == expected
    assert store.credentials(account_id)['refresh_token'] == 'PRIVATE_REFRESH'
    assert store.account(account_id)['state'] == ('expired' if expected == 401 else 'ready')


async def test_forced_concurrent_refresh_only_rotates_once(setup_auth):
    auth, store, account_id = setup_auth
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        await asyncio.sleep(.01)
        assert parse_qs(request.content.decode())['refresh_token'] == ['PRIVATE_REFRESH']
        return httpx.Response(200, json={'access_token': 'PRIVATE_NEW', 'refresh_token': 'PRIVATE_ROTATED'})

    store.set_credentials(account_id, {'_kind': 'desktop-oauth', 'provider': 'gateway',
        'clientId': 'fixture', 'tokenEndpoint': 'https://auth.quick.aws.com/token',
        'tenantUrl': 'https://fixture.quick.aws.com', 'access_token': 'PRIVATE_OLD',
        'refresh_token': 'PRIVATE_REFRESH', 'expires_at': time.time()+3600}, state='ready')
    auth.transport = httpx.MockTransport(handler)
    results = await asyncio.gather(*(auth.credentials(account_id, force=True) for _ in range(8)))
    assert calls == 1
    assert all(r['refresh_token'] == 'PRIVATE_ROTATED' for r in results)


async def test_idc_rotation_persisted_across_reopened_stores(tmp_path):
    store = Store(tmp_path)
    account_id = store.create_account(AccountCreate(name='rotation'))['id']
    current = {'_kind': 'desktop-oauth', 'provider': 'social', 'idc': True,
               'clientId': 'fixture', 'clientSecret': 'PRIVATE_CLIENT',
               'tokenEndpoint': 'https://oidc.us-east-1.amazonaws.com/token',
               'tenantUrl': 'https://fixture.quick.aws.com', 'access_token': 'PRIVATE_ACCESS_0',
               'refresh_token': 'PRIVATE_REFRESH_0', 'expires_at': time.time()+3600}
    store.set_credentials(account_id, current, state='ready')
    store.close()
    for generation in range(3):
        async def handle(request, generation=generation):
            body = json.loads(request.content)
            assert body['refreshToken'] == f'PRIVATE_REFRESH_{generation}'
            return httpx.Response(200, json={'accessToken': f'PRIVATE_ACCESS_{generation+1}',
                'refreshToken': f'PRIVATE_REFRESH_{generation+1}', 'expiresIn': 3600})
        store = Store(tmp_path)
        auth = NativeAuth(store, transport=httpx.MockTransport(handle))
        await auth.credentials(account_id, force=True)
        assert store.credentials(account_id)['refresh_token'] == f'PRIVATE_REFRESH_{generation+1}'
        events = store.auth_events(account_id)
        assert events[0]['event'] == 'token_persisted'
        assert events[0]['details']['matches_response'] is True
        assert events[0]['details']['refresh_sha256'] == events[1]['details']['refresh_sha256']
        assert events[1]['details']['refresh_sha256'] != events[2]['details']['refresh_sha256']
        assert 'PRIVATE_' not in json.dumps(events)
        await auth.close()
        store.close()


@pytest.mark.parametrize('remember_login', [False, True])
def test_expired_status_survives_restart_and_completed_login(setup_auth, remember_login):
    auth, store, account_id = setup_auth
    store.set_credentials(account_id, {'_kind': 'desktop-oauth', 'provider': 'social',
        'access_token': 'PRIVATE_ACCESS', 'refresh_token': 'PRIVATE_REFRESH'}, state='expired')
    store.patch_account(account_id, {'last_error': '原生授权已失效，需要重新授权'})
    if remember_login:
        auth.logins[account_id] = Login(account_id, 'social', 'us-east-1', status='authorized')
    assert auth.status(account_id)['status'] == 'expired'
    assert auth.status(account_id)['error'] == '原生授权已失效，需要重新授权'


async def test_missing_refresh_token_response_preserves_previous_generation(setup_auth):
    auth, store, account_id = setup_auth
    store.set_credentials(account_id, {'_kind': 'desktop-oauth', 'provider': 'social', 'idc': True,
        'clientId': 'fixture', 'tokenEndpoint': 'https://oidc.us-east-1.amazonaws.com/token',
        'tenantUrl': 'https://fixture.quick.aws.com', 'access_token': 'PRIVATE_OLD',
        'refresh_token': 'PRIVATE_REFRESH', 'expires_at': time.time()-1}, state='ready')
    auth.transport = httpx.MockTransport(lambda request: httpx.Response(200, json={
        'accessToken': 'PRIVATE_NEW', 'expiresIn': 3600}))
    await auth.credentials(account_id)
    assert store.credentials(account_id)['refresh_token'] == 'PRIVATE_REFRESH'
    events = store.auth_events(account_id)
    assert events[1]['details']['has_refresh_token'] is False
    assert events[0]['details']['refresh_sha256'] == events[2]['details']['refresh_sha256']
