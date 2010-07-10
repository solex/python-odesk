"""
Python bindings to odesk API
python-odesk version 0.1
(C) 2010 oDesk
"""
VERSION = (0, 1, 1, 'alpha', 1)

from datetime import date

def get_version():
    version = '%s.%s' % (VERSION[0], VERSION[1])
    if VERSION[2]:
        version = '%s.%s' % (version, VERSION[2])
    if VERSION[3:] == ('alpha', 0):
        version = '%s pre-alpha' % version
    else:
        if VERSION[3] != 'final':
            version = "%s %s" % (version, VERSION[3])
            if VERSION[4] != 0:
                version = '%s %s' % (version, VERSION[4])
    return version

import urllib
import urllib2
import hashlib
import cookielib

try:
    import json
except ImportError:
    import simplejson as json


class HTTP400BadRequestError(urllib2.HTTPError):
    pass


class HTTP401UnauthorizedError(urllib2.HTTPError):
    pass


class HTTP403ForbiddenError(urllib2.HTTPError):
    pass


class HTTP404NotFoundError(urllib2.HTTPError):
    pass


class InvalidConfiguredException(Exception):
    pass


class APINotImplementedException(Exception):
    pass


class AuthenticationError(Exception):
    pass


class NotAuthenticatedError(Exception):
    pass


def signed_urlencode(secret, query={}):
    """
    Converts a mapping object to signed url query

    >>> signed_urlencode('some$ecret', {})
    'api_sig=5da1f8922171fbeffff953b773bcdc7f'
    >>> signed_urlencode('some$ecret', {'spam':42,'foo':'bar'})
    'api_sig=11b1fc2e6555297bdc144aed0a5e641c&foo=bar&spam=42'
    """
    message = secret
    for key in sorted(query.keys()):
        message += str(key) + str(query[key])
    query = query.copy()
    query['api_sig'] = hashlib.md5(message).hexdigest()
    return urllib.urlencode(query)


def raise_http_error(e):
    '''Raise custom exception'''
    if e.code == 400:
        raise HTTP400BadRequestError(e.filename, e.code, e.msg,
                                     e.hdrs, None)
    elif e.code == 401:
        raise HTTP401UnauthorizedError(e.filename, e.code, e.msg,
                                       e.hdrs, None)
    elif e.code == 403:
        raise HTTP403ForbiddenError(e.filename, e.code, e.msg,
                                    e.hdrs, None)
    elif e.code == 404:
        raise HTTP404NotFoundError(e.filename, e.code, e.msg,
                                   e.hdrs, None)
    else:
        raise e


class HttpRequest(urllib2.Request):
    """
    A hack around Request class that allows to specify HTTP method explicitly
    """

    def __init__(self, *args, **kwargs):
        #Request is an old-style class, so can't use `super`
        method = kwargs.pop('method', 'GET')
        urllib2.Request.__init__(self, *args, **kwargs)
        self.method = method

    def get_method(self):
        #FIXME: Http method hack. Should be removed once oDesk supports true
        #HTTP methods
        if self.method in ['PUT', 'DELETE']:
            return 'POST'
        #End of hack

        return self.method


class BaseClient(object):
    """
    A basic HTTP client which supports signing of requests as well
    as de-serializing of responses.
    """

    def __init__(self, public_key, secret_key, api_token=None):
        self.public_key = public_key
        self.secret_key = secret_key
        self.api_token = api_token

    def urlencode(self, data={}):
        data = data.copy()
        data['api_key'] = self.public_key
        if self.api_token:
            data['api_token'] = self.api_token
        return signed_urlencode(self.secret_key, data)

    def urlopen(self, url, data={}, method='GET'):
        data = data.copy()

        #FIXME: Http method hack. Should be removed once oDesk supports true
        #HTTP methods
        if method in ['PUT', 'DELETE']:
            data['http_method'] = method.lower()
        #End of hack

        query = self.urlencode(data)
        if method == 'GET':
            url += '?' + query
            request = HttpRequest(url=url, data=None, method=method)
        else:
            request = HttpRequest(url=url, data=query, method=method)
        return urllib2.urlopen(request)

    def read(self, url, data={}, method='GET', format='json'):
        """
        Returns parsed Python object or raises an error
        """
        assert format == 'json', "Only JSON format is supported at the moment"
        url += '.' + format
        try:
            response = self.urlopen(url, data, method)
        except urllib2.HTTPError, e:
            raise_http_error(e)

        if format == 'json':
            result = json.loads(response.read())
        return result


class Client(BaseClient):
    """
    Main API client
    """

    def __init__(self, public_key, secret_key, api_token=None, format='json'):
        self.public_key = public_key
        self.secret_key = secret_key
        self.api_token = api_token
        self.format = format
        #Namespaces
        self.auth = Auth(self)
        self.team = Team(self)
        self.hr = HR2(self)
        self.provider = Provider(self)
        self.mc = Messages(self)
        self.time_reports = TimeReports(self)
        self.finreports = Finreports(self)
        self.otask = OTask(self)

    #Shortcuts for HTTP methods
    def get(self, url, data={}):
        return self.read(url, data, method='GET', format=self.format)

    def post(self, url, data={}):
        return self.read(url, data, method='POST', format=self.format)

    def put(self, url, data={}):
        return self.read(url, data, method='PUT', format=self.format)

    def delete(self, url, data={}):
        return self.read(url, data, method='DELETE', format=self.format)


class SessionClient(Client):
    """
    Session based auth API client
    """
    version = 1
    base_url = 'https://www.odesk.com/api/'    

    def __init__(self, odesk_username=None, odesk_password=None, 
                 session_id=None, cookies=None, format='json'):
        self.odesk_username = odesk_username
        self.odesk_password = odesk_password
        self.session_id = session_id
        self.format = format
        self.cookies = cookies
        #Namespaces
        self.auth = Auth(self)
        self.team = Team(self)
        self.hr = HR2(self)
        self.provider = Provider(self)
        self.mc = Messages(self)
        self.time_reports = TimeReports(self)
        self.finreports = Finreports(self)
        self.otask = OTask(self)

    def urlencode(self, data={}):
        data = data.copy()
        if self.session_id:
            data['session_id'] = self.session_id
        return urllib.urlencode(data)
    
    def urlopen(self, url, data={}, method='GET'):
        cookies = self.cookies or cookielib.CookieJar()
        self.cookies = cookies
        
        urlopener = urllib2.build_opener(urllib2.HTTPRedirectHandler,
                                     urllib2.HTTPCookieProcessor(cookies))
    
        urllib2.install_opener(urlopener)
        
        return super(SessionClient, self).urlopen(url, data, method)
        
    def login(self):
        url = self.base_url + 'auth/v%s/login' % self.version
        data = {'username': self.odesk_username, 
                'password': self.odesk_password}
        try:
            result = self.read(url, data=data, method='POST')
        except urllib2.HTTPError, e:
            if e.code == 401:
                raise AuthenticationError('Wrong username or password')
            else:
                raise e
        self.session_id = result['session']['session_id']
        return result
    
    def logout(self):
        url = self.base_url + 'auth/v%s/login' % self.version
        try:
            result = self.delete(url)
        except urllib2.HTTPError, e:
            raise e
        self.session_id = None
        return result    

class Namespace(object):
    """
    A special 'proxy' class to keep API methods organized
    """

    base_url = 'https://www.odesk.com/api/'
    api_url = None
    version = 1

    def __init__(self, client):
        self.client = client

    def full_url(self, url):
        """
        Gets relative URL of API method and returns a full URL
        """
        return "%s%sv%d/%s" % (self.base_url, self.api_url, self.version, url)

    #Proxied client's methods
    def get(self, url, data={}):
        return self.client.get(self.full_url(url), data)

    def post(self, url, data={}):
        return self.client.post(self.full_url(url), data)

    def put(self, url, data={}):
        return self.client.put(self.full_url(url), data)

    def delete(self, url, data={}):
        return self.client.delete(self.full_url(url), data)


class Auth(Namespace):

    api_url = 'auth/'
    version = 1

    def auth_url(self, frob=None):
        """
        Returns authentication URL to be used in a browser
        In case of desktop (non-web) application a frob is required
        """
        data = {}
        if frob:
            data['frob'] = frob
        url = 'https://www.odesk.com/services/api/auth/?' + \
            self.client.urlencode(data)
        return url

    def get_frob(self):
        url = 'keys/frobs'
        result = self.post(url)
        return result['frob']

    def get_token(self, frob):
        """
        Gets authentication token
        """
        url = 'keys/tokens'
        result = self.post(url, {'frob': frob})
        #TODO: Maybe there's a better way to get user's info?
        return result['token'], result['auth_user']

    def check_token(self):
        url = 'keys/token'
        try:
            result = self.get(url)
            return True
        except HTTP403ForbiddenError:
            return False

    def revoke_token(self):
        url = 'keys/token'
        data = {'api_token': self.client.api_token,
                'api_key': self.client.public_key,}
        return self.delete(url, data)
    
    
class Team(Namespace):

    api_url = 'team/'
    version = 1

    def get_teamrooms(self):
        url = 'teamrooms'
        result = self.get(url)
        teamrooms = result['teamrooms']['teamroom']
        if not isinstance(teamrooms, list):
            teamrooms = [teamrooms]
        return teamrooms

    def get_snapshots(self, team_id, online='now'):
        url = 'teamrooms/%s' % team_id
        result = self.get(url, {'online': online})
        snapshots = result['teamroom']['snapshot']
        if not isinstance(snapshots, list):
            snapshots = [snapshots]
        return snapshots

    def get_workdiaries(self, team_id, username, date=None):
        url = 'workdiaries/%s/%s' % (str(team_id), str(username))
        if date:
            url += '/%s' % str(date)
        result = self.get(url)
        snapshots = result['snapshots']['snapshot']
        if not isinstance(snapshots, list):
            snapshots = [snapshots]
        #not sure we need to return user
        return result['snapshots']['user'], snapshots


class HR2(Namespace):
    """
    HRv2 API
    """
    api_url = 'hr/'
    version = 2

    '''user api'''

    def get_user(self, user_id):
        url = 'users/%s' % str(user_id)
        result = self.get(url)
        return result['user']

    '''company api'''

    def get_companies(self):
        url = 'companies'
        result = self.get(url)
        return result['companies']

    def get_company(self, company_id):
        url = 'companies/%s' % str(company_id)
        result = self.get(url)
        return result['company']

    def get_company_teams(self, company_id):
        url = 'companies/%s/teams' % str(company_id)
        result = self.get(url)
        return result['teams']

    def get_company_tasks(self, company_id):
        raise APINotImplementedException("API doesn't support this call yet")

    def get_company_users(self, company_id, active=True):
        url = 'companies/%s/users' % str(company_id)
        if active:
            data = {'status_in_company': 'active'}
        else:
            data = {'status_in_company': 'inactive'}
        result = self.get(url, data)
        return result['users']

    '''team api'''

    def get_teams(self):
        url = 'teams'
        result = self.get(url)
        return result['teams']

    def get_team(self, team_id, include_users=False):
        url = 'teams/%s' % str(team_id)
        result = self.get(url, {'include_users': include_users})
        #TODO: check how included users returned
        return result['team']

    def get_team_tasks(self, team_id):
        raise APINotImplementedException("API doesn't support this call yet")

    def get_team_users(self, team_id, active=True):
        url = 'teams/%s/users' % str(team_id)
        if active:
            data = {'status_in_team': 'active'}
        else:
            data = {'status_in_team': 'inactive'}
        result = self.get(url, data)
        return result['users']

    def post_team_adjustment(self, team_id, engagement_id, amount, comments,
                             notes):
        '''
        Add bonus to engagement
        '''
        url = 'teams/%s/adjustments' % str(team_id)
        data = {'engagement__reference': engagement_id,
                'amount': amount,
                'comments': comments,
                'notes': notes}
        result = self.post(url, data)
        return result['adjustment']

    '''task api'''

    def get_tasks(self):
        raise APINotImplementedException("API doesn't support this call yet")

    '''userrole api'''

    def get_user_role(self, user_id=None, team_id=None, sub_teams=False):
        '''
        Returns all the user roles that the user has in the teams.
        '''
        data = {}
        if user_id:
            data['user__reference'] = user_id
        if team_id:
            data['team__reference'] = team_id
        data['include_sub_teams'] = sub_teams
        url = 'userroles'
        result = self.get(url, data)
        return result['userroles']

    '''job api'''

    def get_jobs(self):
        url = 'jobs'
        result = self.get(url)
        return result['jobs']

    def get_job(self, job_id):
        url = 'jobs/%s' % str(job_id)
        result = self.get(url)
        return result['job']

    '''offer api'''

    def get_offers(self):
        url = 'offers'
        result = self.get(url)
        return result['offers']

    def get_offer(self, offer_id):
        url = 'offers/%s' % str(offer_id)
        result = self.get(url)
        return result['offer']

    '''engagement api'''

    def get_engagements(self):
        url = 'engagements'
        result = self.get(url)
        return result['engagements']

    def get_engagement(self, engagement_id):
        url = 'engagements/%s' % str(engagement_id)
        result = self.get(url)
        return result['engagement']


class Provider(Namespace):
    api_url = 'profiles/'
    version = 1

    def get_provider(self, provider_ciphertext):
        url = 'providers/%s' % str(provider_ciphertext)
        result = self.get(url)
        return result['profile']

    def get_provider_brief(self, provider_ciphertext):
        url = 'providers/%s/brief' % str(provider_ciphertext)
        result = self.get(url)
        return result['profile']

    def get_providers(self, data={}):
        url = 'search/providers'
        result = self.get(url, data=data)
        return result['providers']

    def get_jobs(self, data={}):
        url = 'search/jobs'
        result = self.get(url, data=data)
        return result['jobs']


class Messages(Namespace):
    api_url = 'mc/'
    version = 1

    def get_trays(self, username=None, paging_offset=0, paging_count=20):
        url = 'trays'
        if paging_offset or not paging_count == 20:
            data = {'paging': '%s;%s' % (str(paging_offset),
                                         str(paging_count))}
        else:
            data = {}

        if username:
            url += '/%s' % str(username)
        result = self.get(url, data=data)
        return result["trays"]

    def get_tray_content(self, username, tray, paging_offset=0,
                         paging_count=20):
        url = 'trays/%s/%s' % (str(username), str(tray))
        if paging_offset or not paging_count == 20:
            data = {'paging': '%s;%s' % (str(paging_offset),
                                         str(paging_count))}
        else:
            data = {}

        result = self.get(url, data=data)
        return result["current_tray"]["threads"]

    def get_thread_content(self, username, thread_id, paging_offset=0,
                           paging_count=20):
        url = 'threads/%s/%s' % (str(username), (thread_id))
        if paging_offset or not paging_count == 20:
            data = {'paging': '%s;%s' % (str(paging_offset),
                                         str(paging_count))}
        else:
            data = {}

        result = self.get(url, data=data)
        return result["thread"]

    def _generate_many_threads_url(self, url, threads_ids):
        new_url = url
        for counter, thread_id in enumerate(threads_ids):
            if counter == 0:
                new_url += '%s' % str(thread_id)
            else:
                new_url += ';%s' % str(thread_id)
        return new_url

    def put_threads_read_unread(self, username, thread_ids, read=True):
        """thread_ids must be a list, even of 1 item"""
        url = 'threads/%s/' % str(username)
        if read:
            data = {'read': 'true'}
        else:
            data = {'read': 'false'}
        result = self.put(self._generate_many_threads_url(url, thread_ids),
                          data=data)
        return result

    def put_threads_read(self, username, thread_ids):
        return self.put_threads_read_unread(username, thread_ids, read=True)

    def put_threads_unread(self, username, thread_ids):
        return self.put_threads_read_unread(username, thread_ids, read=False)

    def put_threads_starred_or_unstarred(self, username, thread_ids,
                                         starred=True):
        """thread_ids must be a list, even of 1 item"""
        url = 'threads/%s/' % str(username)

        if starred:
            data = {'starred': 'true'}
        else:
            data = {'starred': 'false'}

        result = self.put(self._generate_many_threads_url(url, thread_ids),
                          data=data)
        return result

    def put_threads_starred(self, username, thread_ids):
        return self.put_threads_starred_or_unstarred(username,
                                                thread_ids, starred=True)

    def put_threads_unstarred(self, username, thread_ids):
        return self.put_threads_starred_or_unstarred(username,
                                                thread_ids, starred=False)

    def put_threads_deleted_or_undeleted(self, username, thread_ids,
                                         deleted=True):
        """thread_ids must be a list, even of 1 item"""
        url = 'threads/%s/' % str(username)

        if deleted:
            data = {'deleted': 'true'}
        else:
            data = {'deleted': 'false'}

        result = self.put(self._generate_many_threads_url(url, thread_ids),
                          data=data)
        return result

    def put_threads_deleted(self, username, thread_ids):
        return self.put_threads_deleted_or_undeleted(username, thread_ids,
                                                     deleted=True)

    def put_threads_undeleted(self, username, thread_ids):
        return self.put_threads_deleted_or_undeleted(username, thread_ids,
                                                     deleted=False)

    def post_message(self, username, recipients, subject, body,
                     thread_id=None):
        url = 'threads/%s' % str(username)
        if thread_id:
            url += '/%s' % str(thread_id)
        result = self.post(url, data={'recipients': recipients,
                                      'subject': subject,
                                      'body': body})
        return result


class OTask(Namespace):
    api_url = 'otask/'
    version = 1

    def get_company_tasks(self, company_id):
        url = 'tasks/companies/%s/tasks' % str(company_id)
        result = self.get(url)
        return result["tasks"]

    def get_team_tasks(self, company_id, team_id):
        url = 'tasks/companies/%s/teams/%s/tasks' % (str(company_id),
                                                     str(team_id))
        result = self.get(url)
        return result["tasks"]

    def get_user_tasks(self, company_id, team_id, user_id):
        url = 'tasks/companies/%s/teams/%s/users/%s/tasks' % (str(company_id),
                                                    str(team_id), str(user_id))
        result = self.get(url)
        return result["tasks"]

    def get_company_tasks_full(self, company_id):
        url = 'tasks/companies/%s/tasks/full_list' % str(company_id)
        result = self.get(url)
        return result["tasks"]

    def get_team_tasks_full(self, company_id, team_id):
        url = 'tasks/companies/%s/teams/%s/tasks/full_list' %\
                                             (str(company_id), str(team_id))
        result = self.get(url)
        return result["tasks"]

    def get_user_tasks_full(self, company_id, team_id, user_id):
        url = 'tasks/companies/%s/teams/%s/users/%s/tasks/full_list' %\
                                (str(company_id), str(team_id), str(user_id))
        result = self.get(url)
        return result["tasks"]

    def _generate_many_tasks_url(self, task_codes):
        new_url = ''
        for counter, task_code in enumerate(task_codes):
            if counter == 0:
                new_url += '%s' % str(task_code)
            else:
                new_url += ';%s' % str(task_code)
        return new_url

    def get_company_specific_tasks(self, company_id, task_codes):
        url = 'tasks/companies/%s/tasks/%s' % (str(company_id),
                                    self._generate_many_tasks_url(task_codes))
        result = self.get(url)
        return result["tasks"]

    def get_team_specific_tasks(self, company_id, team_id, task_codes):
        url = 'tasks/companies/%s/teams/%s/tasks/%s' %\
                                             (str(company_id), str(team_id),
                                    self._generate_many_tasks_url(task_codes))
        result = self.get(url)
        return result["tasks"]

    def get_user_specific_tasks(self, company_id, team_id, user_id,
                                task_codes):
        url = 'tasks/companies/%s/teams/%s/users/%s/tasks/%s' %\
                                (str(company_id), str(team_id), str(user_id),
                                 self._generate_many_tasks_url(task_codes))
        result = self.get(url)
        return result["tasks"]

    def post_company_task(self, company_id, code, description, url):
        url = 'tasks/companies/%s/tasks' % str(company_id)
        data = {'code': code,
                'description': description,
                'url': url}
        result = self.post(url, data)
        return result

    def post_team_task(self, company_id, team_id, code, description, url):
        url = 'tasks/companies/%s/teams/%s/tasks' % (str(company_id),
                                                     str(team_id))
        data = {'code': code,
                'description': description,
                'url': url}
        result = self.post(url, data)
        return result

    def post_user_task(self, company_id, team_id, user_id, code, description,
                       url):
        url = 'tasks/companies/%s/teams/%s/users/%s/tasks' % (str(company_id),
                                                    str(team_id), str(user_id))
        data = {'code': code,
                'description': description,
                'url': url}
        result = self.post(url, data)
        return result

    def put_company_task(self, company_id, code, description, url):
        url = 'tasks/companies/%s/tasks/%s' % (str(company_id), str(code))
        data = {'code': code,
                'description': description,
                'url': url}
        result = self.put(url, data)
        return result

    def put_team_task(self, company_id, team_id, code, description, url):
        url = 'tasks/companies/%s/teams/%s/tasks/%s' % (str(company_id),
                                                    str(team_id), str(code))
        data = {'code': code,
                'description': description,
                'url': url}
        result = self.put(url, data)
        return result

    def put_user_task(self, company_id, team_id, user_id, code,
                      description, url):
        url = 'tasks/companies/%s/teams/%s/users/%s/tasks/%s' %\
             (str(company_id), str(team_id), str(user_id), str(code))
        data = {'code': code,
                'description': description,
                'url': url}
        result = self.put(url, data)
        return result

    def delete_company_task(self, company_id, task_codes):
        url = 'tasks/companies/%s/tasks/%s' % (str(company_id),
                                    self._generate_many_tasks_url(task_codes))
        return self.delete(url, {})

    def delete_team_task(self, company_id, team_id, task_codes):
        url = 'tasks/companies/%s/teams/%s/tasks/%s' % (str(company_id),
                    str(team_id), self._generate_many_tasks_url(task_codes))
        return self.delete(url, {})

    def delete_user_task(self, company_id, team_id, user_id, task_codes):
        url = 'tasks/companies/%s/teams/%s/users/%s/tasks/%s' %\
                                 (str(company_id), str(team_id), str(user_id),
                                 self. _generate_many_tasks_url(task_codes))
        return self.delete(url, {})

    def delete_all_company_tasks(self, company_id):
        url = 'tasks/companies/%s/tasks/all_tasks' % (str(company_id))
        return self.delete(url, {})

    def delete_all_team_tasks(self, company_id, team_id):
        url = 'tasks/companies/%s/teams/%s/tasks/all_tasks' % (str(company_id),
                                                      str(team_id))
        return self.delete(url, {})

    def delete_all_user_tasks(self, company_id, team_id, user_id):
        url = 'tasks/companies/%s/teams/%s/users/%s/tasks/all_tasks' %\
                     (str(company_id), str(team_id), str(user_id))
        return self.delete(url, {})

    def update_batch_tasks(self, company_id, csv_data):
        url = 'tasks/companies/%s/tasks/batch:%s' % (str(company_id), csv_data)
        return self.put(url, {})


class Q(object):
    '''Simple query constructor'''
    
    def __init__(self, arg1, operator=None, arg2=None):
        self.arg1 = arg1
        self.operator = operator
        self.arg2 = arg2

    def __and__(self, other):
        return self.__class__(self, 'AND', other)

    def __or__(self, other):
        return self.__class__(self, 'OR', other)

    def __eq__(self, other):
        return self.__class__(self, '=', other)

    def __lt__(self, other):
        return self.__class__(self, '<', other)

    def __le__(self, other):
        return self.__class__(self, '<=', other)

    def __gt__(self, other):
        return self.__class__(self, '>', other)

    def __ge__(self, other):
        return self.__class__(self, '>=', other)

    def arg_to_string(self, arg):
        if isinstance(arg, self.__class__):
            if arg.operator:
                return '(%s)' % arg
            else:
                return arg
        elif isinstance(arg, str):
            return "'%s'" % arg
        elif isinstance(arg, date):
            return "'%s'" % arg.isoformat()
        else:
            return str(arg)
        
    def __str__(self):
        if self.operator:
            str1 = self.arg_to_string(self.arg1)
            str2 = self.arg_to_string(self.arg2)
            return '%s %s %s' % (str1, self.operator, str2)
        else:
            return self.arg1
        
class Query(object):
    '''Simple query'''

    DEFAULT_TIMEREPORT_FIELDS = ['worked_on',
                                 'team_id',
                                 'team_name',
                                 'task',
                                 'memo',
                                 'hours',]
    DEFAULT_FINREPORT_FIELDS = ['reference',
                                'date',
                                'buyer_company__id',
                                'buyer_company_name',
                                'buyer_team__id',
                                'buyer_team_name',
                                'provider_company__id',
                                'provider_company_name',
                                'provider_team__id',
                                'provider_team_name',
                                'provider__id',
                                'provider_name',
                                'type',
                                'subtype',
                                'amount']

    def __init__(self, select, where=None, order_by=None):
        self.select  = select
        self.where = where
        self.order_by = order_by

    def __str__(self):
        select  = self.select
        select_str = 'SELECT ' + ', '.join(select)
        where_str = ''
        if self.where:
            where_str = ' WHERE %s' % self.where
        order_by_str = ''
        if self.order_by:
            order_by_str = ' ORDER BY ' + ','.join(self.order_by)
        return ''.join([select_str, where_str, order_by_str])
        

class GdsNamespace(Namespace):
    base_url = 'https://www.odesk.com/gds/'

    def urlopen(self, url, data={}, method='GET'):
        data = data.copy()
        query = self.client.urlencode(data)
        if method == 'GET':
            url += '?' + query
            request = HttpRequest(url=url, data=None, method=method)
            return urllib2.urlopen(request)
        return None

    def read(self, url, data={}, method='GET'):
        """
        Returns parsed Python object or raises an error
        """
        try:
            response = self.urlopen(url, data, method)
        except urllib2.HTTPError, e:
            raise_http_error(e)

        result = json.loads(response.read())
        return result

    def get(self, url, data={}):
        return self.read(self.full_url(url), data, method='GET')


class TimeReports(GdsNamespace):
    api_url = 'timereports/'
    version = 1

    def get_provider_report(self, provider_id, query, hours=False):
        '''get provider's specific time report'''
        url = 'providers/%s' % str(provider_id)
        if hours:
            url += '/hours'
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_company_report(self, company_id, query, hours=False):
        '''get company's specific time report'''
        url = 'companies/%s' % str(company_id)
        if hours:
            url += '/hours'
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_agency_report(self, company_id, agency_id, query, hours=False):
        '''get agency's specific time report'''
        url = 'companies/%s/agencies/%s' % (str(company_id), str(agency_id))
        if hours:
            url += '/hours'
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

class Finreports(GdsNamespace):
    api_url = 'finreports/'
    version = 2

    def get_provider_billings(self, provider_id, query):
        url = 'providers/%s/billings' % str(provider_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_provider_teams_billings(self, provider_team_id, query):
        url = 'provider_teams/%s/billings' % str(provider_team_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_provider_companies_billings(self, provider_company_id, query):
        url = 'provider_companies/%s/billings' % str(provider_company_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_provider_earnings(self, provider_id, query):
        url = 'providers/%s/earnings' % str(provider_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_provider_teams_earnings(self, provider_team_id, query):
        url = 'provider_teams/%s/earnings' % str(provider_team_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_provider_companies_earnings(self, provider_company_id, query):
        url = 'provider_companies/%s/earnings' % str(provider_company_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_buyer_teams_billings(self, buyer_team_id, query):
        url = 'buyer_teams/%s/billings' % str(buyer_team_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_buyer_companies_billings(self, buyer_company_id, query):
        url = 'buyer_companies/%s/billings' % str(buyer_company_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_buyer_teams_earnings(self, buyer_team_id, query):
        url = 'buyer_teams/%s/earnings' % str(buyer_team_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_buyer_companies_earnings(self, buyer_company_id, query):
        url = 'buyer_companies/%s/earnings' % str(buyer_company_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result

    def get_financial_entities(self, accounting_id, query):
        url = 'financial_accounts/%s' % str(accounting_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result
    
    def get_financial_entities_provider(self, provider_id, query):
        url = 'financial_account_owner/%s' % str(provider_id)
        tq = str(query)
        result = self.get(url, data={'tq': tq})
        return result


if __name__ == "__main__":
    import doctest
    doctest.testmod()
