.. _how_to:


***************
How to
***************

.. 
.. _authenticate:

Authenticate
-----------------
To authenticate your web application with the python-odesk, use next code::

    client = odesk.Client('your public key', 'your secret key')
    #redirect your user to the client.auth.auth_url()
    
    #catch frob from the oDesk response to callback
    frob = raw_input('Enter frob: ')
    
    #you can authenticate now 
    auth_token, user = client.auth.get_token(frob)
    
    #Initiating a new client, now with a token. 
    #Not strictly necessary here (could just set `client.auth_token`), but 
    #typical for web apps, which wouldn't probably keep client instances 
    #between requests
    client = odesk.Client('your public key', 'your secret key', auth_token)

.. 
.. _user_information:

Get user's information
----------------------

To get information about provider, use::

    client.provider.get_provider(provider_ciphertext)
    client.provider.get_provider_brief(provider_ciphertext)

To search provider by the query string, use::

    client.provider.get_providers(q={})


.. 
.. _team_information:

Get teams` information
----------------------

After authentication, you can get teams' information from client instance you have::

    client.team.get_teamrooms()
    
To get snapshots::

    client.team.get_snapshots(team_id, online='now')    

To get user's workdiaries inside the team::

    client.team.get_workdiaries(team_id, username, date=None)


.. 
.. _get_messages:

Get trays and messages
----------------------- 

Get user's trays (if user not provided, authenticated user will be taken)::
     
    client.mc.get_trays(username=None, paging_offset=0, paging_count=20)
    
Get content of the tray::
    
    client.mc.get_tray_content(username, tray, paging_offset=0, paging_count=20)
    
Get content of the thread::    
    
    client.mc.get_thread_content(username, thread_id, paging_offset=0, paging_count=20)
    


.. 
.. _send_message:

Send message
----------------------   

To send message::

    client.mc.post_message(username, recipients, subject, body, thread_id=None)
    
Where:

* username = user who is sending message
* recipients = should be python list or tuple of the usernames of recipients    
* subject = subject of the message
* body = body of the message
* thread_id = should be id of the thread if you want your message be a reply inside existing thread

.. 
.. _get_timereports:

Get timereports
----------------------

To get timereports, use, based on the level of the timereports you need::

    client.time_reports.get_provider_report(provider_id, selects, wheres, hours=False):
    client.time_reports.get_company_report(company_id, selects, wheres, hours=False):
    client.time_reports.get_agency_report(company_id, agency_id, selects, wheres, hours=False):

Where:
 * selects = list of fields to select, see http://developers.odesk.com/Time-Reports-API
 * wheres = list of the conditions, see http://developers.odesk.com/Time-Reports-API
 * hours = Limits the query to hour specific elements and hides all financial details. 

For example::

    client.time_reports.get_provider_report('user1', ['worked_on', 
            'assignment_team_id', 'hours', 'earnings', 'earnings_offline', 
            'task', 'memo'],
            ["(", "worked_on", ">", "'2010-05-11'", ")", 'AND', 
             "(", "worked_on", "<=", "'2010-05-13'", ")"])

    client.time_reports.get_provider_report('user2', ['worked_on', 
            'assignment_team_id', 'hours', 'task', 'memo'],
            ["worked_on > '2010-05-11'", 'AND', "worked_on <= '2010-05-13'"],
            hours=True)    

    client.time_reports.get_agency_report('company1', 'agency1', ['worked_on', 
            'assignment_team_id', 'hours', 'earnings', 'earnings_offline', 
            'task', 'memo'],
            ["worked_on > '2010-05-11'", 'AND', "worked_on <= '2010-05-13'"])
  

