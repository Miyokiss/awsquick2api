"""Independent implementation of the Quick 1.2.4660 desktop PKCE handshake.

Only fresh, user-initiated authorization is accepted. No browser profile or
desktop token vault is read. URLs and form fields are version-bound observations;
the original vendor runtime is not required at runtime.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import time
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from .credential_lock import credential_lock

CLIENT_VERSION = '1.2.4660'
TRUSTED_SUFFIXES = ('.amazonaws.com', '.amazoncognito.com', '.aws.amazon.com',
                    '.quick.aws.com', '.signin.aws', '.awsapps.com', '.api.aws')
PLATO_CELL_HOST = re.compile(
    r'qbs-cell[0-9a-f-]+\.dp\.appintegrations\.[a-z]{2}(?:-[a-z]+)+-\d\.prod\.plato\.ai\.aws\.dev')


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def trusted_url(value: str) -> str:
    try:
        if not isinstance(value, str) or any(ch.isspace() or ord(ch) < 32 for ch in value):
            raise ValueError
        url = urlsplit(value)
        host = (url.hostname or '').lower()
        if (url.scheme != 'https' or url.port not in (None, 443) or url.username or url.password
                or url.fragment or not (host in ('quick.aws.com', 'accounts.google.com', 'oauth2.googleapis.com')
                                       or host.endswith(TRUSTED_SUFFIXES) or PLATO_CELL_HOST.fullmatch(host))):
            raise ValueError
    except (ValueError, TypeError):
        raise AuthError(400, '授权发现返回了不受支持的端点') from None
    return value


def discovery_url(value: str, field_name: str) -> str:
    try:
        return trusted_url(value)
    except AuthError:
        try:
            host = urlsplit(value).hostname or '(missing)'
            host = host if re.fullmatch(r'[A-Za-z0-9.:-]{1,253}|\(missing\)', host) else '(invalid)'
        except (ValueError, TypeError):
            host = '(invalid)'
        raise AuthError(400, f'授权发现端点不受支持（{field_name}: {host}）') from None


def jwt_exp(token: str) -> float:
    """Expiry hint only; tokens are never locally accepted as authentication."""
    try:
        body = token.split('.')[1]
        return float(json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))['exp'])
    except (ValueError, KeyError, IndexError, TypeError):
        return 0


@dataclass
class Login:
    account_id: str
    provider: str
    region: str
    nonce: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    state: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    verifier: str = field(default_factory=lambda: secrets.token_urlsafe(64))
    created_at: float = field(default_factory=time.time)
    status: str = 'awaiting_discovery'
    error: str = ''
    manifest: dict = field(default_factory=dict)

    @property
    def challenge(self):
        return base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip('=')


class NativeAuth:
    def __init__(self, store, *, port=18080, transport=None):
        self.store, self.port, self.transport = store, port, transport
        self.logins: dict[str, Login] = {}
        self.locks = defaultdict(asyncio.Lock)
        self.start_lock = asyncio.Lock()
        self.servers = []
        self._operations = set()
        self._maintenance = None
        self._retry_at = {}
        self._failures = defaultdict(int)
        self._closing = False

    def client(self):
        return httpx.AsyncClient(transport=self.transport, timeout=30, trust_env=False,
                                 follow_redirects=False)

    async def _listen(self):
        async with self.start_lock:
            if self.servers:
                return
            try:
                server = await asyncio.start_server(self._http_callback, '127.0.0.1', self.port, limit=16384)
            except OSError:
                raise AuthError(409, f'本机授权回调端口 {self.port} 已被占用，请更换 QUICKPOOL_CALLBACK_PORT') from None
            self.servers.append(server)
            self.port = server.sockets[0].getsockname()[1]
            try:
                self.servers.append(await asyncio.start_server(self._http_callback, '::1', self.port, limit=16384))
            except OSError:
                pass  # IPv4 is sufficient on hosts without IPv6.

    async def begin(self, account_id, provider='social', region='us-east-1'):
        if provider not in ('enterprise', 'social') or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region):
            raise AuthError(422, '授权类型或区域无效')
        await self._listen()
        self.cancel(account_id)
        # Bound retained nonce/state material; expire abandoned browser flows.
        now = time.time()
        self.logins = {k: v for k, v in self.logins.items() if now-v.created_at < 900}
        login = Login(account_id, provider, region)
        self.logins[account_id] = login
        surface = f'desktop:{login.nonce}:{self.port}:{CLIENT_VERSION}'
        if provider == 'enterprise':
            base = f'https://{region}.quicksight.aws.amazon.com/sn/start/app-integrations/quickwork-enterprise-login'
        else:
            base = 'https://quick.aws.com/sn'
        return {'authorization_url': base + '?' + urlencode({'qwSurface': surface}),
                'login_id': login.state, 'status': login.status,
                'expires_at': login.created_at+900, 'callback_port': self.port}

    def cancel(self, account_id):
        self.logins.pop(account_id, None)

    def status(self, account_id):
        account = self.store.account(account_id)
        login = self.logins.get(account_id)
        if login and time.time()-login.created_at > 900:
            login.status, login.error = 'expired', '授权链接已过期，请重新发起授权'
        status = login.status if login else ('authorized' if account['configured'] else 'none')
        error = login.error if login else ''
        if account['state'] == 'expired' and (not login or login.status == 'authorized'):
            status, error = 'expired', account['last_error'] or '原生授权已失效，需要重新授权'
        return {'status': status,
                'provider': account['auth_provider'] or (login.provider if login else ''),
                'has_refresh_token': account['has_refresh_token'],
                'expires_at': account['token_expires_at'], 'error': error}

    @staticmethod
    def _fingerprint(value):
        return hashlib.sha256(value.encode()).hexdigest() if isinstance(value, str) and value else ''

    def _audit(self, account_id, event, **details):
        self.store.auth_event(account_id, event, {'pid': os.getpid(), **details})

    def _find(self, value, *, nonce=False):
        if not isinstance(value, str) or not value:
            raise AuthError(400, '授权回调已失效或校验失败')
        key = 'nonce' if nonce else 'state'
        for login in self.logins.values():
            if hmac.compare_digest(getattr(login, key), value) and time.time()-login.created_at < 900:
                return login
        raise AuthError(400, '授权回调已失效或校验失败')

    async def discovery(self, query):
        login = self._find(query.get('nonce', ''), nonce=True)
        if login.status != 'awaiting_discovery':
            raise AuthError(409, login.error or '此授权发现回调已被使用，请返回 QuickPool 查看状态')
        login.status = 'discovering'
        try:
            return await self._discovery(query)
        except (AuthError, httpx.HTTPError, ValueError, KeyError) as error:
            login.status = 'failed'
            login.error = str(error) if isinstance(error, AuthError) else '原生授权发现暂时失败'
            raise AuthError(getattr(error, 'status', 502), login.error) from None

    async def _discovery(self, query):
        login = self._find(query.get('nonce', ''), nonce=True)
        gateway = 'namespace' in query
        if 'issuerUrl' in query and not gateway:
            # The IdC branch requires dynamic public-client registration.
            manifest = await self._register_idc(query)
            manifest['provider'] = 'social'
        else:
            keys = ('authEndpoint', 'tokenEndpoint', 'clientId', 'clientSecret', 'tenantUrl',
                    'issuer', 'region', 'namespace', 'account')
            manifest = {key: query.get(key, '') for key in keys}
            manifest['provider'] = ('social_gateway' if login.provider == 'social' else 'gateway') if gateway else 'enterprise'
        for key in ('authEndpoint', 'tokenEndpoint', 'tenantUrl'):
            discovery_url(manifest.get(key, ''), key)
        if not manifest.get('clientId'):
            raise AuthError(400, '授权发现缺少 clientId')
        manifest['region'] = manifest.get('region') or login.region
        login.manifest = manifest
        form = {'response_type': 'code', 'client_id': manifest['clientId'],
                'redirect_uri': manifest.get('redirectUri', f'http://localhost:{self.port}'), 'state': login.state,
                'code_challenge': login.challenge, 'code_challenge_method': 'S256'}
        if gateway:
            form['resource'] = manifest['tenantUrl']
        elif manifest['provider'] == 'enterprise':
            # Native's confidential-client branch uses Google's offline consent
            # parameters; public OIDC clients request offline_access in scope.
            if manifest.get('clientSecret'):
                form.update(scope='openid profile email', access_type='offline', prompt='consent')
            else:
                form['scope'] = 'openid profile email offline_access'
        else:
            form['scope'] = 'quicksight:read_write'
            form['prompt'] = 'login'
        login.status = 'awaiting_authorization'
        return manifest['authEndpoint'] + ('&' if '?' in manifest['authEndpoint'] else '?') + urlencode(form)

    async def _register_idc(self, query):
        region = query.get('idcRegion', 'us-east-1')
        if not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-\d', region):
            raise AuthError(400, 'IdC 区域无效')
        issuer = discovery_url(query.get('issuerUrl', ''), 'issuerUrl')
        endpoint = f'https://oidc.{region}.amazonaws.com'
        redirect_uri = f'http://127.0.0.1:{self.port}'
        async with self.client() as client:
            response = await client.post(endpoint+'/client/register', json={
                'clientName': 'AmazonQuick-Desktop', 'clientType': 'public',
                'scopes': ['quicksight:read_write'],
                'grantTypes': ['authorization_code', 'refresh_token'],
                'redirectUris': [redirect_uri], 'issuerUrl': issuer})
        if response.status_code != 200:
            raise AuthError(502, f'AWS IdC 客户端注册失败（HTTP {response.status_code}，{self._error_code(response)}）')
        result = response.json()
        return {'clientId': result['clientId'], 'clientSecret': result.get('clientSecret', ''),
                'tokenEndpoint': endpoint+'/token', 'authEndpoint': endpoint+'/authorize',
                'tenantUrl': query.get('tenantUrl', ''), 'region': region,
                'clientSecretExpiresAt': result.get('clientSecretExpiresAt', 0),
                'redirectUri': redirect_uri, 'idc': True}

    @staticmethod
    def _error_code(response):
        try:
            value = response.json().get('error', '')
        except (ValueError, AttributeError):
            value = ''
        return value if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,80}', value) else 'unknown_error'

    def _token_form(self, credentials, grant, **extra):
        form = {'grant_type': grant, 'client_id': credentials['clientId'], **extra}
        if credentials.get('clientSecret'):
            form['client_secret'] = credentials['clientSecret']
        if credentials['provider'] in ('gateway', 'social_gateway'):
            form['resource'] = credentials['tenantUrl']
        return form

    async def _tokens(self, credentials, form, *, account_id=None):
        trusted_url(credentials['tokenEndpoint'])
        if account_id:
            self._audit(account_id, 'token_request', grant=form['grant_type'],
                        refresh_sha256=self._fingerprint(form.get('refresh_token')),
                        host=urlsplit(credentials['tokenEndpoint']).hostname)
        async with self.client() as client:
            if credentials.get('idc'):
                names = {'grant_type': 'grantType', 'client_id': 'clientId', 'client_secret': 'clientSecret',
                         'redirect_uri': 'redirectUri', 'code_verifier': 'codeVerifier', 'refresh_token': 'refreshToken'}
                response = await client.post(credentials['tokenEndpoint'], json={names.get(k, k): v for k, v in form.items()})
            else:
                response = await client.post(credentials['tokenEndpoint'], data=form)
        if response.status_code != 200:
            code = self._error_code(response)
            if account_id:
                self._audit(account_id, 'token_error', http_status=response.status_code, error_code=code)
            # An HTTP proxy's 401/403 is not the token server judging the grant.
            transient = code in ('temporarily_unavailable', 'server_error', 'slow_down')
            terminal = (400 <= response.status_code < 500 and response.status_code not in (408, 429)
                        and not transient and (code in ('invalid_grant', 'invalid_client',
                            'unauthorized_client', 'invalid_request', 'unsupported_grant_type', 'invalid_scope')
                            or (response.status_code == 400 and code != 'unknown_error')))
            if terminal:
                raise AuthError(401, '原生授权已失效，需要重新授权')
            raise AuthError(503, f'原生令牌交换失败（HTTP {response.status_code}，{code}）')
        tokens = response.json()
        if account_id:
            refresh = tokens.get('refreshToken' if credentials.get('idc') else 'refresh_token')
            self._audit(account_id, 'token_response', http_status=response.status_code,
                        has_refresh_token=isinstance(refresh, str) and bool(refresh),
                        refresh_sha256=self._fingerprint(refresh),
                        access_sha256=self._fingerprint(tokens.get(
                            'accessToken' if credentials.get('idc') else 'access_token')))
        if credentials.get('idc'):
            tokens = {'access_token': tokens.get('accessToken'), 'refresh_token': tokens.get('refreshToken'),
                      'expires_in': tokens.get('expiresIn', 3600)}
        if not isinstance(tokens.get('access_token'), str) or not tokens['access_token']:
            raise AuthError(502, '原生令牌响应缺少 access_token')
        return tokens

    @staticmethod
    def _merge_tokens(credentials, tokens):
        credentials = dict(credentials)
        for key in ('access_token', 'id_token', 'refresh_token'):
            if isinstance(tokens.get(key), str) and tokens[key]:
                credentials[key] = tokens[key]
        deadline = time.time() + max(0, float(tokens.get('expires_in', 3600)))
        exp = jwt_exp(credentials['access_token'])
        credentials['expires_at'] = min(deadline, exp) if exp else deadline
        return credentials

    async def complete(self, query):
        login = self._find(query.get('state', ''))
        async with self.locks[login.account_id], credential_lock(self.store.directory, login.account_id):
            if login.status != 'awaiting_authorization':
                raise AuthError(409, '授权回调已被使用或尚未完成发现')
            if query.get('error') or not query.get('code'):
                code = query.get('error', '')
                detail = code if re.fullmatch(r'[A-Za-z0-9_.:-]{1,80}', code) else 'authorization_cancelled'
                login.status, login.error = 'failed', f'授权未完成（{detail}）'
                raise AuthError(400, login.error)
            login.status = 'exchanging'
            try:
                form = self._token_form(login.manifest, 'authorization_code', code=query['code'],
                                        redirect_uri=login.manifest.get('redirectUri', f'http://localhost:{self.port}'),
                                        code_verifier=login.verifier)
                tokens = await self._tokens(login.manifest, form, account_id=login.account_id)
                credentials = self._merge_tokens(login.manifest | {'_kind': 'desktop-oauth'}, tokens)
                if not credentials.get('refresh_token'):
                    raise AuthError(409, '本次授权未返回 refresh_token，请重新授权并允许离线访问')
                credentials['user_info'] = await self.user_info(credentials)
                expected = self.store.account(login.account_id)['aws_account_id']
                actual = credentials['user_info'].get('awsAccountId', '')
                if expected and actual and expected != actual:
                    raise AuthError(409, '授权得到的 AWS 账号与添加的账号不一致')
                if self.logins.get(login.account_id) is not login:
                    raise AuthError(409, '授权已取消')
                self.store.set_credentials(login.account_id, credentials)
                self._saved(login.account_id, credentials)
                login.status = 'authorized'
                # Erase one-use verifier, nonce and authorization state promptly.
                login.verifier = login.nonce = login.state = ''
            except (AuthError, httpx.HTTPError, ValueError, KeyError) as error:
                login.status, login.error = 'failed', str(error) if isinstance(error, AuthError) else '授权服务暂时不可用'
                raise AuthError(getattr(error, 'status', 502), login.error) from None

    async def user_info(self, credentials):
        endpoint = trusted_url(credentials['tenantUrl']).rstrip('/') + '/integration/quick-work/user-info'
        async with self.client() as client:
            response = await client.post(endpoint, json={}, headers={
                'Authorization': 'Bearer '+credentials['access_token'], 'Content-Type': 'application/json'})
        if response.status_code != 200:
            raise AuthError(403 if response.status_code in (401, 403) else 503, 'Quick 原生用户信息请求失败')
        value = response.json()
        if not isinstance(value, dict):
            raise AuthError(502, 'Quick 用户信息格式不受支持')
        return value.get('userInfo', value)

    async def credentials(self, account_id, *, force=False):
        if self._closing:
            raise AuthError(503, '授权服务正在停止，请稍后重试')
        # Client disconnect/cancellation must not discard a server-rotated token.
        task = asyncio.create_task(self._credentials(account_id, force=force))
        self._operations.add(task)
        def finished(task):
            self._operations.discard(task)
            if not task.cancelled():
                task.exception()  # Retrieve errors even when the caller disconnected.
        task.add_done_callback(finished)
        try:
            return await asyncio.shield(task)
        except (TimeoutError, OSError):
            raise AuthError(503, '原生授权刷新锁暂时不可用，请稍后重试') from None

    async def _credentials(self, account_id, *, force=False):
        observed = self.store.credentials(account_id)
        async with self.locks[account_id], credential_lock(self.store.directory, account_id):
            credentials = self.store.credentials(account_id)
            if not credentials:
                raise AuthError(401, '账号尚未完成原生授权')
            changed = observed and credentials.get('access_token') != observed.get('access_token')
            if (not force or changed) and credentials.get('expires_at', 0) > time.time()+600:
                return credentials
            if (not force and credentials.get('expires_at', 0) > time.time()+60
                    and self._retry_at.get(account_id, 0) > time.monotonic()):
                return credentials
            if not credentials.get('refresh_token'):
                raise AuthError(401, '缺少 refresh_token，需要重新授权')
            try:
                form = self._token_form(credentials, 'refresh_token', refresh_token=credentials['refresh_token'])
                tokens = await self._tokens(credentials, form, account_id=account_id)
                credentials = self._merge_tokens(credentials, tokens)
                account = self.store.account(account_id)
                self.store.set_credentials(account_id, credentials,
                                           state='unverified' if account['state'] == 'expired' else account['state'])
                self._saved(account_id, credentials)
                return credentials
            except AuthError as error:
                if error.status == 401:
                    self.store.patch_account(account_id, {'state': 'expired', 'last_error': str(error)})
                elif not force and credentials.get('expires_at', 0) > time.time()+60:
                    self._retry_at[account_id] = time.monotonic()+60
                    self._audit(account_id, 'refresh_deferred', status=error.status, retry_after=60)
                    return credentials
                raise
            except (httpx.HTTPError, ValueError, KeyError):
                if not force and credentials.get('expires_at', 0) > time.time()+60:
                    self._retry_at[account_id] = time.monotonic()+60
                    self._audit(account_id, 'refresh_deferred', status=503, retry_after=60)
                    return credentials
                raise AuthError(503, '原生令牌刷新暂时失败；已保留 refresh_token 供重试') from None

    def start(self):
        if self._maintenance is None:
            self._maintenance = asyncio.create_task(self._maintain())

    async def maintain_once(self):
        for account in self.store.accounts():
            account_id = account['id']
            if (not account['enabled'] or not account['configured'] or account['state'] == 'expired'
                    or account['token_expires_at'] > time.time()+600
                    or self._retry_at.get(account_id, 0) > time.monotonic()):
                continue
            try:
                fresh = await self.credentials(account_id)
                if fresh.get('expires_at', 0) > time.time()+600:
                    self._failures.pop(account_id, None)
                    self._retry_at.pop(account_id, None)
            except AuthError as error:
                self._failures[account_id] += 1
                delay = min(300, 5 * 2 ** min(self._failures[account_id]-1, 6))
                self._retry_at[account_id] = time.monotonic()+delay
                self._audit(account_id, 'background_refresh_failure', status=error.status,
                            retry_after=delay)
            except (TimeoutError, OSError):
                self._retry_at[account_id] = time.monotonic()+30

    async def _maintain(self):
        while True:
            await self.maintain_once()
            await asyncio.sleep(30)

    def _saved(self, account_id, credentials):
        saved = self.store.credentials(account_id)
        matches = bool(saved) and all(saved.get(k) == credentials.get(k)
                                      for k in ('access_token', 'refresh_token'))
        self._audit(account_id, 'token_persisted', matches_response=matches,
                    refresh_sha256=self._fingerprint(saved.get('refresh_token') if saved else None))
        if not matches:
            raise AuthError(503, '原生令牌保存校验失败，请检查数据目录是否被其他进程使用')

    async def _http_callback(self, reader, writer):
        status, headers, body = 400, {}, '授权回调无效'
        try:
            raw = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
            lines = raw.decode('iso-8859-1').split('\r\n')
            method, target, _ = lines[0].split(' ', 2)
            request_headers = dict(line.split(':', 1) for line in lines[1:] if ':' in line)
            host = next((v.strip().lower() for k, v in request_headers.items() if k.lower() == 'host'), '')
            allowed = {f'localhost:{self.port}', f'127.0.0.1:{self.port}', f'[::1]:{self.port}'}
            if method != 'GET' or host not in allowed or urlsplit(target).netloc:
                raise AuthError(400, '授权回调来源无效')
            url = urlsplit(target)
            pairs = parse_qs(url.query, keep_blank_values=True, max_num_fields=35)
            if any(len(values) != 1 for values in pairs.values()):
                raise AuthError(400, '授权回调包含重复字段')
            query = {k: v[0] for k, v in pairs.items()}
            if url.path == '/callback':
                headers['Location'] = await self.discovery(query)
                status, body = 302, '正在跳转到 Amazon Quick 官方授权页面'
            elif url.path == '/':
                await self.complete(query)
                status, body = 200, '原生授权已完成。请返回 QuickPool 并测试账号。'
            else:
                status, body = 404, '未找到回调路由'
        except AuthError as error:
            status, body = error.status, str(error)
        except (TimeoutError, ValueError, TypeError, KeyError, OSError, httpx.HTTPError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            status, body = 400, '授权回调处理失败，请在 QuickPool 中重新发起授权'
        payload = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>QuickPool 授权</title>'
                   '<body><h1>QuickPool</h1><p>'+html.escape(body)+'</p></body></html>').encode()
        response_headers = {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
                            'Referrer-Policy': 'no-referrer', 'Connection': 'close',
                            'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
                            'Content-Length': str(len(payload)), **headers}
        wire = f'HTTP/1.1 {status} Response\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in response_headers.items())+'\r\n'
        try:
            writer.write(wire.encode('iso-8859-1')+payload)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def close(self):
        self._closing = True
        if self._maintenance:
            self._maintenance.cancel()
            with suppress(asyncio.CancelledError):
                await self._maintenance
            self._maintenance = None
        # Finish in-flight exchanges and their synchronous durable writes first.
        if self._operations:
            await asyncio.gather(*tuple(self._operations), return_exceptions=True)
        for server in self.servers:
            server.close()
            await server.wait_closed()
        self.servers.clear()
        self.logins.clear()
