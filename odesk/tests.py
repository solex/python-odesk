from odesk import *
from mock import Mock, patch
import urllib2

try:
    import json
except ImportError:
    import simplejson as json


def test_signed_urlencode():
    secret_data = {
    'some$ecret': {'query': {},
                   'result': 
                   'api_sig=5da1f8922171fbeffff953b773bcdc7f'},
    'some$ecret': {'query': {'spam': 42,'foo': 'bar'},
                   'result': 
                   'api_sig=11b1fc2e6555297bdc144aed0a5e641c&foo=bar&spam=42'}, 
    'som[&]234e$ecret': {'query': {'spam': 42,'foo': 'bar'},
                   'result': 
                   'api_sig=ac0e1b26f401dd4a5ccbaf7f4ea86b2f&foo=bar&spam=42'},                                      
               }
    for key in secret_data.keys():
        result = signed_urlencode(key, secret_data[key]['query'])
        assert secret_data[key]['result'] == result,\
            " %s returned and should be %s" % (result,\
                                                secret_data[key]['result'])
            
def test_http_request():
    request_methods = [('POST', 'POST'), ('GET', 'GET'), 
                       ('PUT', 'POST'), ('DELETE', 'POST')]
    
    for method in request_methods:
        request = HttpRequest(url="http://url.com", data=None, method=method[0])
        assert request.get_method() == method[1], (request.get_method(),\
                                                   method[1])

def test_base_client():
    public_key = 'public'
    secret_key = 'secret'
    
    bc = BaseClient(public_key, secret_key)
    
    #test urlencode    
    urlresult = bc.urlencode({'spam': 42,'foo': 'bar'})
    encodedkey = 'api_sig=8a0da3cab1dbf7451f38fb5f5aec129c&api_key=public&foo=bar&spam=42'
    assert urlresult == encodedkey, urlresult

sample_json_dict = {u'glossary': 
                    {u'GlossDiv': 
                     {u'GlossList': 
                      {u'GlossEntry': 
                       {u'GlossDef': 
                        {u'GlossSeeAlso': [u'GML', u'XML'], 
                         u'para': u'A meta-markup language'}, 
                         u'GlossSee': u'markup', 
                         u'Acronym': u'SGML', 
                         u'GlossTerm': u'Standard Generalized Markup Language', 
                         u'Abbrev': u'ISO 8879:1986', 
                         u'SortAs': u'SGML', 
                         u'ID': u'SGML'}}, 
                         u'title': u'S'}, 
                         u'title': u'example glossary'}}

                
def return_sample_json():
    return json.dumps(sample_json_dict)
    
def patched_urlopen(request, *args, **kwargs):
    request.read = return_sample_json
    return request
    
@patch('urllib2.urlopen', patched_urlopen)    
def test_base_client_urlopen():
    public_key = 'public'
    secret_key = 'secret'
    
    bc = BaseClient(public_key, secret_key)
    
    #test urlopen
    data = [{'url': 'http://test.url',
             'data': {'foo': 'bar'},
             'method': 'GET',
             'result_data': None,
             'result_url': 'http://test.url?api_sig=ddbf4b10a47ca8300554441dc7c9042b&api_key=public&foo=bar',
             'result_method': 'GET',},
             {'url': 'http://test.url',
             'data': {},
             'method': 'POST',
             'result_data': 'api_sig=ba343f176db8166c4b7e88911e7e46ec&api_key=public',
             'result_url': 'http://test.url',
             'result_method': 'POST',},
             {'url': 'http://test.url',
             'data': {},
             'method': 'PUT',
             'result_data': 'api_sig=52cbaea073a5d47abdffc7fc8ccd839b&api_key=public&http_method=put',
             'result_url': 'http://test.url',
             'result_method': 'POST',},
             {'url': 'http://test.url',
             'data': {},
             'method': 'DELETE',
             'result_data': 'api_sig=8621f072b1492fbd164d808307ba72b9&api_key=public&http_method=delete',
             'result_url': 'http://test.url',
             'result_method': 'POST',},
             ]
                    
    for params in data:
        result = bc.urlopen(url=params['url'], 
                            data=params['data'],
                            method=params['method'])
        assert isinstance(result, HttpRequest), type(result)
        assert result.get_data() == params["result_data"], (result.get_data(),
                                                        params["result_data"]) 
        assert result.get_full_url() == params["result_url"],\
                                                         (result.get_full_url(),
                                                          params["result_url"])
        assert result.get_method() == params["result_method"],\
                                                         (result.get_method(),
                                                          params["result_method"])    

def patched_urlopen_error(request, code=400, *args, **kwargs):
    raise urllib2.HTTPError(url=request.get_full_url(),
                            code=code, msg=str(code), hdrs='', fp=None)
    
def patched_urlopen_400(request, *args, **kwargs):
    return patched_urlopen_error(request, 400, *args, **kwargs)

def patched_urlopen_401(request, *args, **kwargs):
    return patched_urlopen_error(request, 401, *args, **kwargs)

def patched_urlopen_403(request, *args, **kwargs):
    return patched_urlopen_error(request, 403, *args, **kwargs)

def patched_urlopen_404(request, *args, **kwargs):
    return patched_urlopen_error(request, 404, *args, **kwargs)

def patched_urlopen_500(request, *args, **kwargs):
    return patched_urlopen_error(request, 500, *args, **kwargs)

   
@patch('urllib2.urlopen', patched_urlopen_400)
def base_client_read_400(bc, url):
    return bc.read(url)

@patch('urllib2.urlopen', patched_urlopen_401)
def base_client_read_401(bc, url):
    return bc.read(url)
                                             
@patch('urllib2.urlopen', patched_urlopen_403)
def base_client_read_403(bc, url):
    return bc.read(url)

@patch('urllib2.urlopen', patched_urlopen_404)
def base_client_read_404(bc, url):
    return bc.read(url)

@patch('urllib2.urlopen', patched_urlopen_500)
def base_client_read_500(bc, url):
    return bc.read(url)

                                                             
@patch('urllib2.urlopen', patched_urlopen)   
def test_base_client_read():
    """
    test cases:
      method default (get) - other we already tested
      format json|yaml ( should produce error)
      codes 200|400|401|403|404|500
    """
    public_key = 'public'
    secret_key = 'secret'
    
    bc = BaseClient(public_key, secret_key)    
    test_url = 'http://test.url'
    
    #produce error on format other then json
    class NotJsonException(Exception):
        pass
    
    try:
        bc.read(url=test_url, format='yaml')
        raise NotJsonException()
    except NotJsonException, e:
        assert 0, "BaseClient.read() doesn't produce error on yaml format"
    except:
       pass 
    
    #test get, all ok
    result = bc.read(url=test_url)
    assert result == sample_json_dict, result
    
    #test get, 400 error
    try:
        result = base_client_read_400(bc=bc, url=test_url)
    except HTTP400BadRequestError, e:
        pass
    except Exception, e:
        assert 0, "Incorrect exception raised for 400 code: " + str(e) 

    #test get, 401 error
    try:
        result = base_client_read_401(bc=bc, url=test_url)
    except HTTP401UnauthorizedError, e:
        pass
    except Exception, e:
        assert 0, "Incorrect exception raised for 401 code: " + str(e) 
    
    #test get, 403 error
    try:
        result = base_client_read_403(bc=bc, url=test_url)
    except HTTP403ForbiddenError, e:
        pass
    except Exception, e:
        assert 0, "Incorrect exception raised for 403 code: " + str(e)
            
    #test get, 404 error
    try:
        result = base_client_read_404(bc=bc, url=test_url)
    except HTTP404NotFoundError, e:
        pass
    except Exception, e:
        assert 0, "Incorrect exception raised for 404 code: " + str(e)
    
    #test get, 500 error
    try:
        result = base_client_read_500(bc=bc, url=test_url)
    except urllib2.HTTPError, e:
        if e.code == 500:
            pass
        else:
            assert 0, "Incorrect exception raised for 500 code: " + str(e)
    except Exception, e:
        assert 0, "Incorrect exception raised for 500 code: " + str(e)    
    

@patch('urllib2.urlopen', patched_urlopen)    
def test_client():
    public_key = 'public'
    secret_key = 'secret'
    api_token = 'some_token'
    c = Client(public_key, secret_key, api_token)
    test_url = "http://test.url"

    result = c.get(test_url)
    assert result == sample_json_dict, result

    result = c.post(test_url)
    assert result == sample_json_dict, result

    result = c.put(test_url)
    assert result == sample_json_dict, result

    result = c.delete(test_url)
    assert result == sample_json_dict, result
    
    
@patch('urllib2.urlopen', patched_urlopen)    
def test_namespace():
    public_key = 'public'
    secret_key = 'secret'
    api_token = 'some_token'
    c = Client(public_key, secret_key, api_token)
    test_url = "http://test.url"  
    
    ns = Namespace(c)
    
    #test full_url
    full_url = ns.full_url('test')
    assert full_url == 'https://www.odesk.com/api/Nonev1/test', full_url
    
    result = ns.get(test_url)
    assert result == sample_json_dict, result

    result = ns.post(test_url)
    assert result == sample_json_dict, result

    result = ns.put(test_url)
    assert result == sample_json_dict, result

    result = ns.delete(test_url)
    assert result == sample_json_dict, result

def setup_auth():
    public_key = 'public'
    secret_key = 'secret'
    api_token = 'some_token'
    c = Client(public_key, secret_key, api_token)
    test_url = "http://test.url"   
    
    return Auth(c)
    
def test_auth():
    
    au = setup_auth()
    
    #test full_url
    full_url = au.full_url('test')
    assert full_url == 'https://www.odesk.com/api/auth/v1/test', full_url

    auth_url = au.auth_url('test')
    auth_url_result = 'https://www.odesk.com/services/api/auth/?frob=test&api_key=public&api_sig=42b7f18cbc5c16b1f037dbad241f2a6b&api_token=some_token'
    assert auth_url == auth_url_result, auth_url

frob_dict = {'frob': 'test'}

def return_frob_json():
    return json.dumps(frob_dict)

def patched_urlopen_frob(request, *args, **kwargs):
    request.read = return_frob_json
    return request

@patch('urllib2.urlopen', patched_urlopen_frob)  
def test_auth_get_frob(): 
    #test get_frob
    au = setup_auth()
    assert au.get_frob() == frob_dict['frob'] 
    
token_dict = {'token': 'testtoken', 'auth_user': 'test_auth_user'}
    
def return_token_json():
    return json.dumps(token_dict)

def patched_urlopen_token(request, *args, **kwargs):
    request.read = return_token_json
    return request

@patch('urllib2.urlopen', patched_urlopen_token)  
def test_auth_get_token(): 
    #test get_frob
    au = setup_auth()
    token, auth_user = au.get_token('test_token')
    assert token == token_dict['token'], token
    assert auth_user == token_dict['auth_user'], auth_user 
    

@patch('urllib2.urlopen', patched_urlopen_token)      
def test_check_token_true(): 
    #check if ok  
    au = setup_auth()
    assert au.check_token(), au.check_token()

@patch('urllib2.urlopen', patched_urlopen_403)
def test_check_token_false():
    #check if denied
    au = setup_auth()
    assert not au.check_token(), au.check_token()


teamrooms_dict = {'teamrooms': 
                  {'teamroom': {u'team_ref': u'1', 
                  u'name': u'oDesk', 
                  u'recno': u'1', 
                  u'parent_team_ref': u'1', 
                  u'company_name': u'oDesk', 
                  u'company_recno': u'1', 
                  u'teamroom_api': u'/api/team/v1/teamrooms/odesk:some.json', 
                  u'id': u'odesk:some'}},
                  'teamroom': {'snapshot': 'test snapshot'}
                               }

def return_teamrooms_json():
    return json.dumps(teamrooms_dict)

def patched_urlopen_teamrooms(request, *args, **kwargs):
    request.read = return_teamrooms_json
    return request

@patch('urllib2.urlopen', patched_urlopen_teamrooms)  
def test_team():
    public_key = 'public'
    secret_key = 'secret'
    api_token = 'some_token'
    c = Client(public_key, secret_key, api_token)
    test_url = "http://test.url"
    
    te = Team(c)
    
    #test full_url
    full_url = te.full_url('test')
    assert full_url == 'https://www.odesk.com/api/team/v1/test', full_url
    
    #test get_teamrooms
    assert te.get_teamrooms() == teamrooms_dict['teamrooms']['teamroom'],\
         te.get_teamrooms()

    #test get_snapshots
    assert te.get_snapshots(1) == [teamrooms_dict['teamroom']['snapshot']],\
         te.get_snapshots(1)


userroles = {u'userrole': 
             [{u'parent_team__reference': u'1', 
              u'user__id': u'testuser', u'team__id': u'test:t', 
              u'reference': u'1', u'team__name': u'te', 
              u'company__reference': u'1', 
              u'user__reference': u'1', 
              u'user__first_name': u'Test', 
              u'user__last_name': u'Development', 
              u'parent_team__id': u'testdev', 
              u'team__reference': u'1', u'role': u'manager', 
              u'affiliation_status': u'none', u'engagement__reference': u'', 
              u'parent_team__name': u'TestDev', u'has_team_room_access': u'1', 
              u'company__name': u'Test Dev', 
              u'permissions': 
                {u'permission': [u'manage_employment', u'manage_recruiting']}}]}

engagement = {u'status': u'active', 
              u'buyer_team__reference': u'1', u'provider__reference': u'2', 
              u'job__title': u'development', u'roles': {u'role': u'buyer'}, 
              u'reference': u'1', u'engagement_end_date': u'', 
              u'fixed_price_upfront_payment': u'0',
              u'fixed_pay_amount_agreed': u'1.00', 
              u'provider__id': u'test_provider', 
              u'buyer_team__id': u'testteam:aa', 
              u'engagement_job_type': u'fixed-price', 
              u'job__reference': u'1', u'provider_team__reference': u'', 
              u'engagement_title': u'Developer', 
              u'fixed_charge_amount_agreed': u'0.01', 
              u'created_time': u'0000', u'provider_team__id': u'', 
              u'offer__reference': u'', 
              u'engagement_start_date': u'000', u'description': u''}

engagements = {u'lister': 
               {u'total_items': u'10', u'query': u'', 
                u'paging': {u'count': u'10', u'offset': u'0'}, u'sort': u''},
               u'engagement': [engagement, engagement],
               }           

offer = {u'provider__reference': u'1', 
         u'signed_by_buyer_user': u'', 
         u'reference': u'1', u'job__description': u'python', 
         u'buyer_company__name': u'Python community', 
         u'engagement_title': u'developer', u'created_time': u'000', 
         u'buyer_company__reference': u'2', u'buyer_team__id': u'testteam:aa', 
         u'interview_status': u'in_process', u'buyer_team__reference': u'1', 
         u'signed_time_buyer': u'', u'has_buyer_signed': u'', 
         u'signed_time_provider': u'', u'created_by': u'testuser', 
         u'job__reference': u'2', u'engagement_start_date': u'00000', 
         u'fixed_charge_amount_agreed': u'0.01', u'provider_team__id': u'', 
         u'status': u'', u'signed_by_provider_user': u'', 
         u'engagement_job_type': u'fixed-price', u'description': u'', 
         u'provider_team__name': u'', u'fixed_pay_amount_agreed': u'0.01', 
         u'candidacy_status': u'active', u'has_provider_signed': u'', 
         u'message_from_provider': u'', u'my_role': u'buyer', 
         u'key': u'~~0001', u'message_from_buyer': u'', 
         u'buyer_team__name': u'Python community 2', 
         u'engagement_end_date': u'', u'fixed_price_upfront_payment': u'0', 
         u'created_type': u'buyer', u'provider_team__reference': u'', 
         u'job__title': u'translation', u'expiration_date': u'', 
         u'engagement__reference': u''}

offers = {u'lister': 
          {u'total_items': u'10', u'query': u'', u'paging': 
           {u'count': u'10', u'offset': u'0'}, u'sort': u''}, 
           u'offer': [offer, offer]}

job = {u'subcategory': u'Development', u'reference': u'1', 
       u'buyer_company__name': u'Python community', 
       u'job_type': u'fixed-price', u'created_time': u'000', 
       u'created_by': u'test', u'duration': u'', 
       u'last_candidacy_access_time': u'', 
       u'category': u'Web', 
       u'buyer_team__reference': u'169108', u'title': u'translation', 
       u'buyer_company__reference': u'1', u'num_active_candidates': u'0', 
       u'buyer_team__name': u'Python community 2', u'start_date': u'000', 
       u'status': u'filled', u'num_new_candidates': u'0', 
       u'description': u'test', u'end_date': u'000', 
       u'public_url': u'http://www.odesk.com/jobs/~~0001', 
       u'visibility': u'invite-only', u'buyer_team__id': u'testteam:aa', 
       u'num_candidates': u'1', u'budget': u'1000', u'cancelled_date': u'', 
       u'filled_date': u'0000'}

jobs = [job, job]

task =  {u'reference': u'test', u'company_reference': u'1',
          u'team__reference': u'1', u'user__reference': u'1',
          u'code': u'1', u'description': u'test task',
          u'url': u'http://url.odesk.com/task', u'level': u'1',} 
tasks = [task, task]

auth_user = {u'first_name': u'TestF', u'last_name': u'TestL', 
             u'uid': u'testuser', u'timezone_offset': u'0', 
             u'timezone': u'Europe/Athens', u'mail': u'test_user@odesk.com', 
             u'messenger_id': u'', u'messenger_type': u'yahoo'} 

user = {u'status': u'active', u'first_name': u'TestF', 
        u'last_name': u'TestL', u'reference': u'0001', 
        u'timezone_offset': u'10800', 
        u'public_url': u'http://www.odesk.com/users/~~000', 
        u'is_provider': u'1', 
        u'timezone': u'GMT+02:00 Athens, Helsinki, Istanbul', 
        u'id': u'testuser'}

team = {u'status': u'active', u'parent_team__reference': u'0', 
         u'name': u'Test', 
         u'reference': u'1', 
         u'company__reference': u'1', 
         u'id': u'test', 
         u'parent_team__id': u'test_parent', 
         u'company_name': u'Test', u'is_hidden': u'', 
         u'parent_team__name': u'Test parent'}

company = {u'status': u'active',  
             u'name': u'Test', 
             u'reference': u'1', 
             u'company_id': u'1',
             u'owner_user_id': u'1', }
                        
hr_dict = {u'auth_user': auth_user,
           u'server_time': u'0000', 
           u'user': user,
           u'team': team, 
           u'company': company, 
            u'teams': [team, team],
            u'companies': [company, company],
            u'users': [user, user],
            u'tasks': task,
            u'userroles': userroles,
            u'engagements': engagements,
            u'engagement': engagement,
            u'offer': offer,
            u'offers': offers,   
            u'job': job,
            u'jobs': jobs,}

def return_hr_json():
    return json.dumps(hr_dict)

def patched_urlopen_hr(request, *args, **kwargs):
    request.read = return_hr_json
    return request

@patch('urllib2.urlopen', patched_urlopen_hr)  
def test_get_hrv2():
    public_key = 'public'
    secret_key = 'secret'
    api_token = 'some_token'
    c = Client(public_key, secret_key, api_token)
    test_url = "http://test.url"
    
    hr = c.hr
    
    #test get_user
    assert hr.get_user(1) == hr_dict[u'user'], hr.get_user(1)

    #test get_companies
    assert hr.get_companies() == hr_dict[u'companies'], hr.get_companies()
    
    #test get_company
    assert hr.get_company(1) == hr_dict[u'company'], hr.get_company(1)
    
    #test get_company_teams
    assert hr.get_company_teams(1) == hr_dict['teams'], hr.get_company_teams(1)

    #test get_company_users
    assert hr.get_company_users(1) == hr_dict['users'], hr.get_company_users(1)

    #test get_company_tasks
    try:
        assert hr.get_company_tasks(1) == hr_dict['tasks'],\
            hr.get_company_tasks(1)
    except APINotImplementedException, e:
        pass
    except:
        assert 0, "APINotImplementedException not raised"
     
    #test get_teams
    assert hr.get_teams() == hr_dict[u'teams'], hr.get_teams()
            
    #test get_team
    assert hr.get_team(1) == hr_dict[u'team'], hr.get_team(1)
        
    #test get_team_users
    assert hr.get_team_users(1) == hr_dict[u'users'], hr.get_team_users(1)
    
    #test get_team_tasks
    try:
        assert hr.get_team_tasks(1) == hr_dict['tasks'], hr.get_team_tasks(1)
    except APINotImplementedException, e:
        pass
    except:
        assert 0, "APINotImplementedException not raised"
     
    #test get_user_role
    assert hr.get_user_role(user_id=1) == hr_dict['userroles'],\
                                                 hr.get_user_role(user_id=1)
    assert hr.get_user_role(team_id=1) == hr_dict['userroles'],\
                                                 hr.get_user_role(team_id=1)
    assert hr.get_user_role() == hr_dict['userroles'], hr.get_user_role()

        
    try:
        assert hr.get_tasks() == hr_dict['tasks'], hr.get_tasks()
    except APINotImplementedException, e:
        pass
    except:
        assert 0, "APINotImplementedException not raised"      
        
        
    #test get_jobs
    assert hr.get_jobs() == hr_dict[u'jobs'], hr.get_jobs()
    assert hr.get_job(1) == hr_dict[u'job'], hr.get_job(1)
    
    #test get_offers
    assert hr.get_offers() == hr_dict[u'offers'], hr.get_offers()
    assert hr.get_offer(1) == hr_dict[u'offer'], hr.get_offer(1)
 
    #test get_engagements
    assert hr.get_engagements() == hr_dict[u'engagements'], hr.get_engagements()
    assert hr.get_engagement(1) == hr_dict[u'engagement'], hr.get_engagement(1)
    
adjustments = {u'adjustment' : {u'reference': '100'}}

def return_hradjustment_json():
    return json.dumps(adjustments)

def patched_urlopen_hradjustment(request, *args, **kwargs):
    request.read = return_hradjustment_json
    return request

@patch('urllib2.urlopen', patched_urlopen_hradjustment)  
def test_hrv2_post_adjustment():
    public_key = 'public'
    secret_key = 'secret'
    api_token = 'some_token'
    c = Client(public_key, secret_key, api_token)
    test_url = "http://test.url"
    
    hr = c.hr
    result = hr.post_team_adjustment(1, 2, 100000, 'test', 'test note')
    assert result == adjustments[u'adjustment'], result
    
       