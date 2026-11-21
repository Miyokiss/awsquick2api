"""Passphrase encrypted, versioned account transfer; local keys never leave Store."""
from __future__ import annotations

import base64
import json
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .models import AccountCreate
from .native_auth import AuthError, trusted_url

AAD = b'QuickPool-account-export-v1'


class TransferError(ValueError):
    pass


def derive(passphrase, salt):
    if not isinstance(passphrase,str) or not 12 <= len(passphrase) <= 1024:
        raise TransferError('迁移密码须为 12–1024 个字符')
    return Scrypt(salt=salt,length=32,n=2**15,r=8,p=1).derive(passphrase.encode('utf-8'))


def export_accounts(store, passphrase, account_ids=None):
    accounts = store.accounts()
    ids = set(account_ids) if account_ids is not None else {a['id'] for a in accounts if a['configured']}
    if not ids or len(ids) > 100 or ids - {a['id'] for a in accounts}:
        raise TransferError('请选择 1–100 个已授权账号')
    result = []
    for account in accounts:
        if account['id'] not in ids:
            continue
        credentials = store.credentials(account['id'])
        if not credentials or not credentials.get('refresh_token'):
            raise TransferError('所选账号缺少可迁移的原生刷新凭据')
        result.append({'id':account['id'],'config':{k:account[k] for k in (
            'name','login_url','weight','max_concurrency')},'enabled':account['enabled'],'credentials':credentials})
    salt, nonce = os.urandom(16), os.urandom(12)
    raw = json.dumps({'version':1,'created_at':time.time(),'accounts':result},ensure_ascii=False).encode('utf-8')
    encrypted = AESGCM(derive(passphrase,salt)).encrypt(nonce,raw,AAD)
    return {'format':'quickpool-accounts','version':1,'kdf':'scrypt-32768-8-1','cipher':'AES-256-GCM',
            **{k:base64.b64encode(v).decode() for k,v in [('salt',salt),('nonce',nonce),('ciphertext',encrypted)]}}


def import_accounts(store, envelope, passphrase):
    try:
        if (envelope.get('format') != 'quickpool-accounts' or envelope.get('version') != 1
                or envelope.get('kdf') != 'scrypt-32768-8-1' or envelope.get('cipher') != 'AES-256-GCM'):
            raise ValueError
        salt, nonce, data = (base64.b64decode(envelope[k],validate=True) for k in ('salt','nonce','ciphertext'))
        if len(salt) != 16 or len(nonce) != 12 or not 16 <= len(data) <= 3*1024*1024:
            raise ValueError
        decoded = json.loads(AESGCM(derive(passphrase,salt)).decrypt(nonce,data,AAD))
        rows = decoded['accounts']
        if decoded.get('version') != 1 or not isinstance(rows,list) or not 1 <= len(rows) <= 100:
            raise ValueError
        validated = []
        seen = set()
        for row in rows:
            aid = str(uuid.UUID(row['id']))
            config = AccountCreate.model_validate(row['config'])
            credentials = row['credentials']
            if aid in seen or not isinstance(row['enabled'],bool):
                raise TypeError
            seen.add(aid)
            if (credentials.get('_kind') != 'desktop-oauth' or credentials.get('provider') not in (
                    'social','aidp','gateway','social_gateway','enterprise')
                    or not isinstance(credentials.get('refresh_token'),str) or not credentials['refresh_token']
                    or not isinstance(credentials.get('clientId'),str) or not credentials['clientId']):
                raise ValueError
            for name in ('tenantUrl','tokenEndpoint'):
                trusted_url(credentials[name])
            token = urlsplit(credentials['tokenEndpoint'])
            # Token-bearing refresh requests must go to an AWS token service, never an arbitrary trusted login URL.
            if not token.hostname.endswith(('.amazonaws.com','.amazoncognito.com','.quick.aws.com','.aws.amazon.com')):
                raise ValueError
            if token.query or not re.search(r'(?:^|/)(?:token|oauth2/token)$',token.path):
                raise ValueError
            if not isinstance(credentials.get('expires_at',0),(int,float)):
                raise TypeError
            validated.append((aid,config,row['enabled'],credentials))
    except TransferError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, InvalidTag, AuthError, OverflowError):
        raise TransferError('迁移文件或密码无效；未导入任何账号') from None
    with store.lock:
        if len(store.accounts())+len(validated) > 100 or any(store.account(aid) for aid,_,_,_ in validated):
            raise TransferError('账号冲突或超过 100 个；未覆盖现有账号')
        try:
            with store.db:
                for aid,config,enabled,credentials in validated:
                    secret = store.cipher.encrypt(json.dumps(credentials,ensure_ascii=False).encode('utf-8'))
                    identity = credentials.get('user_info',{}).get('awsAccountId','')
                    if not isinstance(identity,str) or not re.fullmatch(r'\d{12}',identity):
                        identity = ''
                    store.db.execute('INSERT INTO accounts(id,name,login_url,aws_account_id,enabled,weight,'
                        'max_concurrency,state,created_at,secret,auth_type,auth_provider,token_expires_at,has_refresh_token) '
                        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (aid,config.name,config.login_url,identity,enabled,
                        config.weight,config.max_concurrency,'unverified',time.time(),secret,'native',
                        credentials['provider'],credentials.get('expires_at',0),True))
        except sqlite3.Error:
            raise TransferError('导入保存失败；事务已回滚') from None
    return {'imported':[aid for aid,_,_,_ in validated],'state':'unverified'}


def main():
    import argparse
    import getpass
    import sys

    from .store import Store
    parser = argparse.ArgumentParser(description='QuickPool 加密账号迁移；先停止使用该数据目录的网关')
    parser.add_argument('action',choices=('export','import'))
    parser.add_argument('file',type=Path)
    parser.add_argument('--data-dir',type=Path,default=Path(os.getenv('QUICKPOOL_DATA_DIR','data')))
    parser.add_argument('--passphrase-stdin',action='store_true',help='从标准输入读取密码，不要在命令行中写密码')
    args = parser.parse_args()
    secret = sys.stdin.readline().rstrip('\r\n') if args.passphrase_stdin else getpass.getpass('迁移密码（至少12位）: ')
    store = Store(args.data_dir)
    try:
        if args.action == 'export':
            result = export_accounts(store,secret)
            with args.file.open('x',encoding='utf-8') as f:
                json.dump(result,f,ensure_ascii=False,indent=2)
            args.file.chmod(0o600)
            print('已导出加密账号文件；不含本机管理/API/加密密钥')
        else:
            result = import_accounts(store,json.loads(args.file.read_text(encoding='utf-8')),secret)
            print('已导入',len(result['imported']),'个账号；实际测试通过后进入账号池')
    except (TransferError,OSError,ValueError) as error:
        parser.exit(1,str(error)+'\n')
    finally:
        store.close()


if __name__ == '__main__':
    main()
