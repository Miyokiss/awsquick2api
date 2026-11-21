import asyncio
import time

import httpx
import pytest

from quickpool.models import AccountCreate
from quickpool.native_auth import AuthError, NativeAuth
from quickpool.pool import Pool
from quickpool.store import Store


def configured(store):
    account = store.create_account(AccountCreate(name='lifecycle'))
    store.set_credentials(account['id'], {
        '_kind': 'desktop-oauth', 'provider': 'social', 'idc': True,
        'clientId': 'fixture', 'clientSecret': 'FIXTURE_CLIENT',
        'tokenEndpoint': 'https://oidc.us-east-1.amazonaws.com/token',
        'tenantUrl': 'https://fixture.quick.aws.com',
        'access_token': 'FIXTURE_OLD', 'refresh_token': 'FIXTURE_REFRESH',
        'expires_at': time.time() - 1}, state='ready')
    return account['id']


async def test_cancelled_caller_does_not_discard_rotated_token(tmp_path):
    store = Store(tmp_path)
    account_id = configured(store)
    entered, release = asyncio.Event(), asyncio.Event()

    async def handler(request):
        entered.set()
        await release.wait()
        return httpx.Response(200, json={'accessToken': 'FIXTURE_NEW',
            'refreshToken': 'FIXTURE_ROTATED', 'expiresIn': 3600})

    auth = NativeAuth(store, transport=httpx.MockTransport(handler))
    task = asyncio.create_task(auth.credentials(account_id))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    release.set()
    await auth.close()
    assert store.credentials(account_id)['refresh_token'] == 'FIXTURE_ROTATED'
    store.close()


@pytest.mark.parametrize('status', [401, 403, 503])
async def test_proxy_failure_is_not_terminal_oauth_rejection(tmp_path, status):
    store = Store(tmp_path)
    account_id = configured(store)
    auth = NativeAuth(store, transport=httpx.MockTransport(
        lambda request: httpx.Response(status, text='proxy unavailable')))
    try:
        with pytest.raises(AuthError) as error:
            await auth.credentials(account_id)
        assert error.value.status == 503
        assert store.account(account_id)['state'] == 'ready'
    finally:
        await auth.close()
        store.close()


async def test_chat_auth_status_alone_does_not_expire_refresh_grant(tmp_path):
    store = Store(tmp_path)
    account_id = configured(store)
    pool = Pool(store)
    await pool.release(account_id, 401, message='handshake rejected')
    assert store.account(account_id)['state'] == 'cooldown'
    store.patch_account(account_id, {'state': 'expired'})
    await pool.release(account_id, 401, message='confirmed invalid_grant')
    assert store.account(account_id)['state'] == 'expired'
    store.close()


async def test_distinct_auth_instances_serialize_rotation(tmp_path):
    import json

    store = Store(tmp_path)
    account_id = configured(store)
    requests = []

    async def handler(request):
        requests.append(json.loads(request.content)['refreshToken'])
        await asyncio.sleep(.05)
        return httpx.Response(200, json={'accessToken': 'FIXTURE_NEW',
            'refreshToken': 'FIXTURE_ROTATED', 'expiresIn': 3600})

    auth1 = NativeAuth(store, transport=httpx.MockTransport(handler))
    auth2 = NativeAuth(store, transport=httpx.MockTransport(handler))
    await asyncio.gather(auth1.credentials(account_id), auth2.credentials(account_id))
    assert requests == ['FIXTURE_REFRESH']
    await auth1.close()
    await auth2.close()
    store.close()


async def test_proactive_refresh_uses_ten_minute_lead_and_retains_valid_bearer(tmp_path):
    store = Store(tmp_path)
    account_id = configured(store)
    old = store.credentials(account_id) | {'expires_at': time.time()+590}
    store.set_credentials(account_id, old, state='ready')
    calls = []
    auth = NativeAuth(store, transport=httpx.MockTransport(
        lambda request: (calls.append(request), httpx.Response(503))[1]))
    try:
        await auth.maintain_once()
        assert len(calls) == 1
        assert store.account(account_id)['state'] == 'ready'
        assert (await auth.credentials(account_id))['access_token'] == 'FIXTURE_OLD'
        await auth.maintain_once()
        assert len(calls) == 1  # Retry is deferred for 60 seconds, not every request.
    finally:
        await auth.close()
        store.close()


async def test_chat_401_refreshes_and_retries_once_with_new_bearer(tmp_path):
    from quickpool.native_upstream import Upstream

    store = Store(tmp_path)
    account_id = configured(store)
    store.set_credentials(account_id, store.credentials(account_id) | {
        'provider': 'gateway', 'expires_at': time.time()+3600}, state='ready')
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path == '/token':
            return httpx.Response(200, json={'accessToken': 'FIXTURE_NEW',
                'refreshToken': 'FIXTURE_ROTATED', 'expiresIn': 3600})
        assert request.url.path == '/v1/discovery'
        if request.headers['authorization'] == 'Bearer FIXTURE_OLD':
            return httpx.Response(401)
        assert request.headers['authorization'] == 'Bearer FIXTURE_NEW'
        return httpx.Response(200, json={'cellHost': 'https://cell.quick.aws.com'})

    transport = httpx.MockTransport(handler)
    auth = NativeAuth(store, transport=transport)
    upstream = Upstream(store, auth, transport=transport)

    async def reply(*args, **kwargs):
        yield 'recovered'

    upstream._stream = reply
    try:
        result = [text async for text in upstream.stream(store.account(account_id),
                  [{'role': 'user', 'content': 'fixture'}])]
        assert result == ['recovered']
        assert calls == ['/v1/discovery', '/token', '/v1/discovery']
        assert store.credentials(account_id)['refresh_token'] == 'FIXTURE_ROTATED'
    finally:
        await auth.close()
        store.close()


async def test_os_lock_excludes_another_process_then_releases(tmp_path):
    import sys

    from quickpool.credential_lock import credential_lock

    script = '''import asyncio,sys
from pathlib import Path
from quickpool.credential_lock import credential_lock
async def check():
    try:
        async with credential_lock(Path(sys.argv[1]), 'fixture-account', timeout=.15):
            print('ACQUIRED')
    except TimeoutError:
        print('BLOCKED')
asyncio.run(check())
'''
    async def child():
        process = await asyncio.create_subprocess_exec(sys.executable, '-c', script, str(tmp_path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode == 0
        return stdout.strip()

    async with credential_lock(tmp_path, 'fixture-account'):
        assert await child() == b'BLOCKED'
    assert await child() == b'ACQUIRED'
