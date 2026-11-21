import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from quickpool.models import AccountCreate
from quickpool.native_auth import NativeAuth
from quickpool.native_upstream import Upstream, UpstreamError
from quickpool.store import Store


async def test_personal_idc_uses_tenant_and_access_token_without_gateway_discovery(tmp_path):
    store = Store(tmp_path)
    account = store.create_account(AccountCreate(name='fixture'))
    try:
        store.set_credentials(account['id'], {'_kind':'desktop-oauth','provider':'social',
            'tenantUrl':'https://qbs-cell11111111-2222-4333-8444-555555555555.dp.appintegrations.us-east-1.prod.plato.ai.aws.dev',
            'access_token':'PRIVATE_ACCESS','refresh_token':'PRIVATE_REFRESH','expires_at':time.time()+3600})
        def forbidden(request):
            raise AssertionError('AIDP must not call Gateway discovery')
        upstream = Upstream(store,NativeAuth(store),transport=httpx.MockTransport(forbidden))
        session = await upstream.session(account['id'])
        url, headers = session.connection()
        parsed = urlsplit(url)
        assert parsed.hostname == urlsplit(store.credentials(account['id'])['tenantUrl']).hostname
        assert parsed.path == '/streaming/quickwork-chat-bidirectional-stream'
        query = parse_qs(parsed.query)
        assert query['token'] == ['PRIVATE_ACCESS']
        assert query['surfaceType'] == ['QUICK_WORK_DESKTOP_WINDOWS']
        assert query['workingSessionId'] and query['outpostId']
        assert 'Authorization' not in headers
    finally:
        store.close()


async def test_gateway_discovery_preserves_retry_after(tmp_path):
    store = Store(tmp_path)
    account = store.create_account(AccountCreate(name='fixture'))
    try:
        store.set_credentials(account['id'],{'_kind':'desktop-oauth','provider':'gateway',
            'tenantUrl':'https://a.quick.aws.com','access_token':'PRIVATE',
            'refresh_token':'PRIVATE_REFRESH','expires_at':time.time()+3600})
        transport = httpx.MockTransport(lambda request: httpx.Response(429,headers={'Retry-After':'120'}))
        with pytest.raises(UpstreamError) as error:
            await Upstream(store,NativeAuth(store),transport=transport).session(account['id'])
        assert error.value.status == 429 and error.value.retry_after == 120
    finally:
        store.close()
