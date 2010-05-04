import urllib, urllib2
import hashlib

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


class HttpRequest(urllib2.Request):
    """
    A hack around Request class that allows to specify HTTP method explicitly
    """
    
    def __init__(self, *args, **kwargs):
        #Request is an old-style class, so can't use `super`
        method = kwargs.pop('method','GET')
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

    #Shortcuts for HTTP methods
    def get(self, url, data={}):
        return self.read(url, data, method='GET', format=self.format)

    def post(self, url, data={}):
        return self.read(url, data, method='POST', format=self.format)
        
    def put(self, url, data={}):
        return self.read(url, data, method='PUT', format=self.format)
        
    def delete(self, url, data={}):
        return self.read(url, data, method='DELETE', format=self.format)



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
        url = 'https://www.odesk.com/services/api/auth/?'+self.client.urlencode(data)
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
        result = self.post(url, {'frob':frob})
        #TODO: Maybe there's a better way to get user's info?
        return result['token'], result['auth_user']

    def check_token(self):
        url = 'keys/token'
        try:
            result = self.get(url)
            return True
        except HTTP403ForbiddenError:
            return False


class Team(Namespace):
    
    api_url = 'team/'
    version = 1
    
    def get_teamrooms(self):
        url = 'teamrooms'
        result = self.get(url)
        return result['teamrooms']['teamroom']

    def get_snapshots(self, team_id, online='now'):
        url = 'teamrooms/%s' % team_id
        result = self.get(url, {'online':online})
        snapshots = result['teamroom']['snapshot']
        if not isinstance(snapshots, list):
            snapshots = [snapshots]
        return snapshots


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
              
    def get_company_users(self, company_id,  active=True):
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
    
    def post_team_adjustment(self, team_id, engagement_id, amount, comments, notes):
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
            data = {'user__reference': user_id}
        elif team_id:
            data = {'team__reference': team_id}     
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
    
if __name__ == "__main__":
    import doctest
    doctest.testmod()
