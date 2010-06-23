import odesk

PUBLIC_KEY = None
SECRET_KEY = None


#TODO: Desktop app example (check if it's working at all - wasn't last time)

def fin_reports(public_key, secret_key):
    print "Emulating web-based app"
    #Instantiating a client without an auth token
    client = odesk.Client(public_key, secret_key)
    print "Please to this URL (authorize the app if necessary):"
    print client.auth.auth_url()
    print "After that you should be redirected back to your app URL with " + \
          "additional ?frob= parameter"
    frob = raw_input('Enter frob: ') 
    auth_token, user = client.auth.get_token(frob)
    print "Authenticated user:"
    print user
    #Instantiating a new client, now with a token. 
    #Not strictly necessary here (could just set `client.auth_token`), but 
    #typical for web apps, which wouldn't probably keep client instances 
    #between requests
    client = odesk.Client(public_key, secret_key, auth_token)
    print client.finreports.get_financial_entities_provider('user1', ['date', 
        'assignment__reference', 'assignment_name', 
        'description', 'provider__id', 'provider_name', 'amount'],
            ["date", ">", "'2010-05-11'", ])

 
if __name__ == '__main__':
    public_key = PUBLIC_KEY or raw_input('Enter public key: ')
    secret_key = SECRET_KEY or raw_input('Enter secret key: ')

    fin_reports(public_key, secret_key)

