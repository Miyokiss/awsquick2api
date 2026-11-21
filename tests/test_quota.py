import time

import httpx

from quickpool.quota import Quotas, gateway_usage, normalize_usage


def test_missing_quota_not_fabricated_and_fields_whitelisted():
    for value in (None,{}, {'other':'private'}):
        assert normalize_usage(value)['status']=='unavailable'
    summary = normalize_usage({'monthlyUsage':{'availableUnits':540,'provisionedUnits':720,
                              'usedPercentage':25,'PRIVATE_FIELD':'PRIVATE_VALUE'},
                               'sessionUsedPercentage':50,'sessionResumeInMinutes':4})
    assert summary['monthly']['availableUnits']==540
    assert summary['session']=={'usedPercentage':50,'resumeInMinutes':4}
    assert 'PRIVATE' not in str(summary)
    assert normalize_usage({'monthlyUsage':{'availableUnits':float('nan')}})['status']=='unavailable'


def test_gateway_entitlement_unwrap():
    summary = normalize_usage(gateway_usage({'entitlements':[{'unitType':'AUTOMATION_AGENT_HOUR_UNIT',
        'numMinsAvailable':540,'numMinsProvisioned':720,'overageAllowed':True,
        'rateLimitStatus':{'isThrottled':True,'consumptionPercentage':65,'estimatedMinutesToResume':8}}]}))
    assert summary['monthly']['usedPercentage']==25
    assert summary['monthly']['availableUnits']==540 and summary['session']['resumeInMinutes']==8
    assert normalize_usage(gateway_usage({'entitlements':[]}))['status']=='unavailable'


async def test_personal_quota_native_request_and_safe_failure():
    class Auth:
        async def credentials(self,account_id):
            return {'provider':'social','tenantUrl':'https://fixture.quick.aws.com','access_token':'PRIVATE_TOKEN'}
    calls=[]
    def handler(request):
        calls.append(request)
        assert request.method=='POST' and request.url.path=='/integration/quick-work/user-info'
        assert request.content==b'{"excludeUserInfo":true}'
        assert request.headers['authorization']=='Bearer PRIVATE_TOKEN'
        return httpx.Response(200,json={'usageSummary':{'monthlyUsage':{'availableUnits':599,'provisionedUnits':600}},
                                        'userEmail':'PRIVATE_EMAIL'})
    quotas = Quotas(Auth(),httpx.MockTransport(handler))
    before = time.time()
    result = await quotas.refresh('fixture')
    assert result['monthly']['availableUnits']==599 and result['updated_at']>=before
    assert 'PRIVATE' not in str(result) and len(calls)==1
    assert quotas.cached('fixture')==result
    quotas.transport=httpx.MockTransport(lambda request:httpx.Response(401,text='PRIVATE_BODY'))
    failed = await quotas.refresh('fixture')
    assert failed['status']=='unavailable' and 'monthly' not in failed and 'PRIVATE' not in str(failed)
