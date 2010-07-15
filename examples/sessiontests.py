"""
Python bindings to odesk API
python-odesk version 0.1
(C) 2010 oDesk
"""
import odesk

USERNAME = None
PASSWORD = None


#TODO: Desktop app example (check if it's working at all - wasn't last time)

def web_based_app(username, password):
    print "Emulating web-based app"
    #Instantiating a client without an auth token
    client = odesk.SessionClient(username, password)
    print client.login()
    print "HR: teams"
    print client.hr.get_teams()
    print client.logout()
    print "HR: teams"
    print client.hr.get_teams()    
    
   

if __name__ == '__main__':
    username = USERNAME or raw_input('Enter username: ')
    password = PASSWORD or raw_input('Enter pasword: ')

    web_based_app(username, password)

