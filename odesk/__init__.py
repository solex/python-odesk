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
        urllib2.Request.__init__(self,*args, **kwargs)
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
    Default client that uses JSON to talk to oDesk APIs
    """

    def get(self, url, data={}):
        return self.read(url, data, method='GET', format='json')

    def post(self, url, data={}):
        return self.read(url, data, method='POST', format='json')
        
    def put(self, url, data={}):
        return self.read(url, data, method='PUT', format='json')
        
    def delete(self, url, data={}):
        return self.read(url, data, method='DELETE', format='json')

    def auth_url(self, frob=None):
        data = {}
        if frob:
            data['frob'] = frob
        url = 'https://www.odesk.com/services/api/auth/?'+self.urlencode(data)
        return url 

    def get_frob(self):
        url = 'https://www.odesk.com/api/auth/v1/keys/frobs'
        result = self.post(url)
        return result['frob']

    def get_token(self, frob):
        url = 'https://www.odesk.com/api/auth/v1/keys/tokens'
        result = self.post(url, {'frob':frob})
        #TODO: Maybe there's a better way to get user's info
        return result['token'], result['auth_user']

    def check_token(self):
        url = 'https://www.odesk.com/api/auth/v1/keys/token'
        try:
            result = self.get(url)
            return True
        except HTTP403ForbiddenError:
            return False

    def get_team_rooms(self):
        url = 'https://www.odesk.com/api/team/v1/teamrooms'
        result = self.get(url)
        return result['teamrooms']['teamroom']

    def get_snapshots(self, team_id, online='now'):
        url = 'https://www.odesk.com/api/team/v1/teamrooms/%s' % team_id
        result = self.get(url, {'online':online})
        snapshots = result['teamroom']['snapshot']
        if not isinstance(snapshots, list):
            snapshots = [snapshots]
        return snapshots



    

if __name__ == "__main__":
    import doctest
    doctest.testmod()
