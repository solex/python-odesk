.. _full_list:


********************************
Full list of classes and methods
********************************

.. 
.. _exceptions:

Exceptions
-----------------

* HTTP400BadRequestError(urllib2.HTTPError)
* HTTP401UnauthorizedError(urllib2.HTTPError)
* HTTP403ForbiddenError(urllib2.HTTPError)
* HTTP404NotFoundError(urllib2.HTTPError)
* InvalidConfiguredException(Exception)
* APINotImplementedException(Exception)

.. _base:

Base and support classes and methods
------------------------------------

* def raise_http_error(e)

Raise appropriate exception depending on the code returned by urllib2

* class HttpRequest(urllib2.Request)

A hack around Request class that allows to specify HTTP method explicitly

* class BaseClient(object)

A basic HTTP client which supports signing of requests as well as de-serializing of responses.

* class Namespace

* class GdsNamespace


.. _client:
    
Client
---------------------

* class Client(BaseClient)

 * def __init__(self, public_key, secret_key, api_token=None, format='json')
  
 * Variables available inside Client:
 
  * public_key
  * secret_key
  * api_token
  * format
  * auth
  * team
  * hr
  * provider
  * mc
  * time_reports
  * otask

.. _classes:
    
Other classes
---------------------

* Auth(Namespace)

 * auth_url
 * get_frob
 * get_token
 * check_token

* Team(Namespace)

 * get_teamrooms(self)
 * get_snapshots(self, team_id, online='now')
 * get_workdiaries(self, team_id, username, date=None)

* HR2(Namespace)

 * get_user(self, user_id)
 * get_companies(self)
 * get_company(self, company_id)
 * get_company_teams(self, company_id)
 * get_company_tasks(self, company_id) - Not implemented in API
 * get_company_users(self, company_id,  active=True)
 * get_teams(self)
 * get_team(self, team_id, include_users=False)
 * get_team_tasks(self, team_id) - Not implemented in API
 * get_team_users(self, team_id, active=True)
 * post_team_adjustment(self, team_id, engagement_id, amount, comments, notes)
 * get_tasks(self) - Not implemented in API
 * get_user_role(self, user_id=None, team_id=None, sub_teams=False)
 * get_jobs(self)
 * get_job(self, job_id)
 * get_offers(self)
 * get_offer(self, offer_id)
 * get_engagements(self)
 * get_engagement(self, engagement_id)

* Provider(Namespace)

 * get_provider(self, provider_ciphertext)
 * get_provider_brief(self, provider_ciphertext)
 * get_providers (q='')

* Messages(Namespace)

 * get_trays(self, username=None, paging_offset=0, paging_count=20)
 * get_tray_content(self, username, tray, paging_offset=0, paging_count=20)
 * get_thread_content(self, username, thread_id, paging_offset=0, paging_count=20)
 * put_threads_read(self, username, thread_ids)
 * put_threads_unread(self, username, thread_ids)
 * put_threads_starred(self, username, thread_ids)
 * put_threads_unstarred(self, username, thread_ids)
 * put_threads_deleted(self, username, thread_ids)
 * put_threads_undeleted(self, username, thread_ids)
 * post_message(self, username, recipients, subject, body, thread_id=None)

* OTask(Namespace)

 * get_company_tasks(self, company_id)
 * get_team_tasks(self, company_id, team_id)
 * get_user_tasks(self, company_id, team_id, user_id)
 * get_company_tasks_full(self, company_id)
 * get_team_tasks_full(self, company_id, team_id)
 * get_user_tasks_full(self, company_id, team_id, user_id)
 * get_company_specific_tasks(self, company_id, task_codes)
 * get_team_specific_tasks(self, company_id, team_id, task_codes)
 * get_user_specific_tasks(self, company_id, team_id, user_id, task_codes)
 * post_company_task(self, company_id, code, description, url)
 * post_team_task(self, company_id, team_id, code, description, url)
 * post_user_task(self, company_id, team_id, user_id, code, description, url)
 * put_company_task(self, company_id, code, description, url)
 * put_team_task(self, company_id, team_id, code, description, url)
 * put_user_task(self, company_id, team_id, user_id, code, description, url)
 * delete_company_task(self, company_id, task_codes)
 * delete_team_task(self, company_id, team_id, task_codes)
 * delete_user_task(self, company_id, team_id, user_id, task_codes)
 * delete_all_company_tasks(self, company_id)
 * delete_all_team_tasks(self, company_id, team_id)
 * delete_all_user_tasks(self, company_id, team_id, user_id)
 * update_batch_tasks(self, company_id, csv_data)

* TimeReports(GdsNamespace)

 * get_provider_report(self, provider_id, selects, wheres, hours=False)
 * get_company_report(self, company_id, selects, wheres, hours=False)
 * get_agency_report(self, company_id, agency_id, selects, wheres, hours=False)
 * selects and wheres are lists of params. They are joined while building the param string