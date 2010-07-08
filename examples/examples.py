"""
Python bindings to odesk API
python-odesk version 0.1
(C) 2010 oDesk
"""
import odesk

PUBLIC_KEY = None
SECRET_KEY = None


#TODO: Desktop app example (check if it's working at all - wasn't last time)

def web_based_app(public_key, secret_key):
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
    print "Team rooms:"
    print client.team.get_teamrooms()
    #HRv2 API
    print "HR: companies" 
    print client.hr.get_companies()
    print "HR: teams"
    print client.hr.get_teams()
    print "HR: offers"
    print client.hr.get_offers()
    print "HR: get_engagements"
    print client.hr.get_engagements()   
    print "HR: userroles"
    print client.hr.get_user_role()
    print "Get jobs"
    print client.provider.get_jobs({'q': 'python'})    
    print "Revoke access"
    print client.auth.revoke_token()    


if __name__ == '__main__':
    public_key = PUBLIC_KEY or raw_input('Enter public key: ')
    secret_key = SECRET_KEY or raw_input('Enter secret key: ')

    web_based_app(public_key, secret_key)

