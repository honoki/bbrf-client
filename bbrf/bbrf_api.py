import requests
import base64
import json
from slackclient import SlackClient


class BBRFApi:
    BBRF_API = None
    auth = None
    doctypes = ['ip', 'domain', 'program', 'agent', 'url', 'service', 'config']
    sc = None
    discord_webhook = None
    
    requests_session = None
    
    def __init__(self, couchdb_url, user, pwd, slack_token = None, discord_webhook = None, ignore_ssl_errors = False):
        auth = user+':'+pwd
        self.auth = 'Basic '+base64.b64encode(auth.encode('utf-8')).decode('utf-8')
        self.requests_session = requests.Session()
        if slack_token:
            self.sc = SlackClient(slack_token)
        if discord_webhook:
            self.discord_webhook = discord_webhook
        if ignore_ssl_errors:
            from urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
            self.requests_session.verify = False
        self.BBRF_API = couchdb_url
    
    '''
    Create a new program.
    '''
    def create_new_program(self, program_name=None, disabled=False, passive_only=False, tags=[]):
        if not program_name:
            return
        else:
            program = {"type": "program", "disabled": disabled, "passive_only": passive_only, "inscope": [], "outscope": []}
            if tags:
                tag_map = {x.split(':', 1)[0]: x.split(':', 1)[1] for x in tags}
                program['tags'] = tag_map
            r = self.requests_session.put(self.BBRF_API+'/'+program_name, json.dumps(program), headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
    
    '''
    Get a list of all domains, filtered by program name if provided.
    
    @todo: generalize this and get_ips by general function get_document_by_program_name with additional paramter doctype
    '''
    def get_domains_by_program_name(self, program_name=None):
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/domains?reduce=false&key="'+program_name+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/domains?reduce=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    '''
    Get a list of all urls, filtered by program or hostname if provided.
    '''
    def get_urls_by_hostname(self, hostname=None):
        if hostname:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/urls_by_hostname?reduce=false&key="'+hostname+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/urls_by_hostname?reduce=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        # print all url, status, content_length if status and content length are set    
        return [" ".join([str(x) for x in r['value'] if x]) for r in r.json()['rows']]
    
    def get_urls_by_program(self, program=None):
        if program:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/urls_by_program?reduce=false&key="'+program+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/urls_by_program?reduce=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        # print all url, status, content_length if status and content length are set
        return [" ".join([str(x) for x in r['value'] if x]) for r in r.json()['rows']]
    
    
    '''
    Get a list of all services, filtered by program name if provided.
    '''
    def get_services_by_program_name(self, program_name=None):
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/services?reduce=false&key="'+program_name+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/services?reduce=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    '''
    Get all documents of a certain type
    '''
    def get_documents(self, doctype, program_name = None):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        if doctype == 'agent':
            return self.get_agents()
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s?reduce=false&key="'+program_name+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s?reduce=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    '''
    @todo put restrictions on 'view' parameter, should only allow lowercase and _
    '''
    def get_documents_view(self, program_name, doctype, view):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s_'+view+'?reduce=false&key="'+program_name+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s_'+view+'?reduce=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    '''
    Get a list of all ips, filtered by program name if provided.
    '''
    def get_ips_by_program_name(self, program_name=None):
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/ips?reduce=false&key="'+program_name+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/ips?reduce=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    '''
    Get a list of all programs.
    '''
    def get_programs(self, show_disabled=False):
        if show_disabled:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/programs?reduce=false', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/programs?reduce=false&key=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    def get_program_scope(self, program_name):
        r = self.requests_session.get(self.BBRF_API+'/'+program_name, headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return r.json()['inscope'], r.json()['outscope']
    
    def update_program_scope(self, program_name, inscope, outscope):
        r = self.requests_session.get(self.BBRF_API+'/'+program_name, headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        program = r.json()
        # only update if different!
        if program['inscope'] != inscope or program['outscope'] != outscope:
            program['inscope'] = inscope
            program['outscope'] = outscope
            r = self.requests_session.put(self.BBRF_API+'/'+program_name+'?rev='+program['_rev'], json.dumps(program), headers={"Authorization": self.auth})
            if 'error' in r.json():
                raise Exception(r.json()['error'])
            
    def get_program_blacklist(self, program_name=None):
        r = self.requests_session.get(self.BBRF_API+'/'+program_name, headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        if 'blacklist' not in r.json():
            return []
        return r.json()['blacklist']
    
    def update_program_blacklist(self, program_name, blacklist):
        r = self.requests_session.get(self.BBRF_API+'/'+program_name, headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        program = r.json()
        program['blacklist'] = blacklist
        r = self.requests_session.put(self.BBRF_API+'/'+program_name+'?rev='+program['_rev'], json.dumps(program), headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
            
    '''
    Get a list of all agents.
    '''
    def get_agents(self):
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/agents', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return r.json()['rows']
    
    '''
    Register a new agent.
    '''
    def register_agent(self, name):
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/agents', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['key'] for r in r.json()['rows']]
    
    '''
    Add a list of documents to a program in bulk.
    '''
    def add_documents(self, doctype, identifiers, program_name, source=None, tags=[]):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        # Create documents in bulk
        bulk = {"docs": []}
        doc = {}
        
        relname = ''
        if doctype == 'ip':
            relname = 'domains'
        elif doctype == 'domain':
            relname = 'ips'
        
        for docid in identifiers.keys():
            doc = {
                '_id': docid,
                'program': program_name,
                'type': doctype
            }
            if relname:
                if len(identifiers[docid])>0:
                    doc[relname] = list(filter(None,identifiers[docid]))  # filter out the empty values
                else:
                    doc[relname] = []
            
            else:
                # in order to support urls and general flexibility,
                # this needs to support arbitrary keys to be added to the JSON document
                for key in identifiers[docid]:
                    if key not in ['_rev', '_id']:
                        doc[key] = identifiers[docid][key]
                
            if source:
                doc['source'] = source
                
            if tags:
                tag_map = {x.split(':', 1)[0]: x.split(':', 1)[1] for x in tags}
                doc['tags'] = tag_map
                
            bulk['docs'].append(doc)
        
        r = self.requests_session.post(
            self.BBRF_API+'/_bulk_docs', json.dumps(bulk),
            headers={"Authorization": self.auth, "Content-Type": "application/json"}
        )
        
        # return (success,failed) with identifiers of new docs and docs that failed due to conflict
        return (
            [doc['id'] for doc in r.json() if 'error' not in doc],
            [doc['id'] for doc in r.json() if 'error' in doc and doc['error'] == 'conflict']
        )
        
        #if 'error' in r.json():
        #    raise Exception(r.json()['error'])
    
    '''
    Get the identifier of a document based on a set of properties defined in propmap
    '''
    def get_document_id_by_properties(self, doctype, propmap):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        docs = self.get_documents(doctype)
        for doc in docs:
            matches = True
            for prop in propmap.keys():
                if prop not in doc or propmap[prop] != doc[prop]:
                    matches = False
            if matches:
                return doc['id']
                
    '''
    Remove a document from the database, based on a document property.
    '''
    def remove_document(self, doctype, document):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
            
        if type(document) is dict:
            document = self.get_document_id_by_properties(doctype, document)
            # print(document)
            
        # Need to encode the document so it can handle CIDR ranges including /
        r = self.requests_session.get(self.BBRF_API+'/'+requests.utils.quote(document, safe=''), headers={"Authorization": self.auth})
        # print(r.json())
        if 'error' in r.json() and r.json()['error'] != 'not_found':
            raise Exception(r.json()['error'])
        elif 'error' in r.json() and r.json()['error'] == 'not_found':
            return
        if 'type' in r.json() and not r.json()['type'] == doctype:
            raise Exception('The specified document (type: '+r.json()['type']+') is not of the requested type '+doctype)
            # print("here4")
        if '_rev' in r.json():
            r = self.requests_session.delete(self.BBRF_API+'/'+requests.utils.quote(document, safe='')+'?rev='+r.json()['_rev'], headers={"Authorization": self.auth})
            if 'error' in r.json() and r.json()['error'] != 'not_found':
                raise Exception(r.json()['error'])
                
    '''
    Return a raw version of a document by id
    '''
    def get_document(self, docid):
        r = self.requests_session.get(self.BBRF_API+'/'+requests.utils.quote(docid, safe=''), headers={"Authorization": self.auth})
        if 'error' in r.json() and r.json()['error'] == 'not_found':
            return None
        return r.text
        
    '''
    Update a document, based on the document identifier.
    updates contains a map with keyname => [] that will
    be appended to the document.
    '''
    def update_document(self, doctype, document, updates):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        r = self.requests_session.get(self.BBRF_API+'/'+requests.utils.quote(document, safe=''), headers={"Authorization": self.auth})
        if 'error' in r.json() and r.json()['error'] != 'not_found':
            raise Exception(r.json()['error'])
        elif 'error' in r.json() and r.json()['error'] == 'not_found':
            return
        if 'type' in r.json() and not r.json()['type'] == doctype:
            raise Exception('The specified document (type: '+r.json()['type']+') is not of the requested type '+doctype)
        if '_rev' in r.json():
            
            document_changed = False
            
            original_document = r.json()
            for prop in updates.keys():
                if prop not in original_document:
                    print('[Warning] The update specifies a key that does not exist: '+prop)
                    if type(updates[prop]) is list:
                        original_document[prop] = []  # initiate the property list if it doesn't exist
                    else:
                        original_document[prop] = None
                if not type(original_document[prop]) is type(updates[prop]):
                    print('The updated key does not have the right type. Cannot update data of '+prop)
                    continue
                # if it's a list, append
                if type(original_document[prop]) is list:
                    for val in updates[prop]:         
                        if val not in original_document[prop]:
                            document_changed = True
                            original_document[prop].append(val)
                    # filter out empty values
                    original_document[prop] = list(filter(None, original_document[prop]))
                # if it's not a list or a dict, replace
                elif not isinstance(original_document[prop], (list, dict)):
                    if not original_document[prop] == updates[prop]:
                        document_changed = True
                        original_document[prop] = updates[prop]
                        
            if document_changed:
                r = self.requests_session.put(
                    self.BBRF_API+'/'+requests.utils.quote(document, safe='')+'?rev='+r.json()['_rev'],
                    json.dumps(original_document),
                    headers={"Authorization": self.auth, "Content-Type": "application/json"}
                )
                
                if 'error' in r.json():
                    raise Exception(r.json()['error'])
                
                return document
        
    '''
    Update documents in bulk
    The provided batch_updates need to be a dict of updates mapping the id to the dict of updates
    '''
    def update_documents(self, doctype, batch_updates):

        # first, get the latest revisions of each of the listed documents
        r = self.requests_session.post(self.BBRF_API+'/_all_docs?include_docs=true', json.dumps({'keys': [x for x in batch_updates.keys()]}), headers={"Authorization": self.auth, 'Content-Type': 'application/json'})
        
        current = {a['key']: a['doc'] for a in r.json()['rows'] if 'doc' in a and a['doc']}
        updates = {x['key']: batch_updates[x['key']].update({'_id': x['key'], '_rev':x['value']['rev']}) or batch_updates[x['key']] for x in r.json()['rows'] if 'doc' in x and x['doc']}
        
        to_be_updated = []
        
        for x in current.keys():
            if not self.docs_are_equal(current[x], updates[x]):
                to_be_updated.append(updates[x])
        
        # TODO:
        # check current doctype against document.type
        for updates in to_be_updated:
            original_document = current[updates['_id']]
            
            if not original_document['type'] == doctype:
                print('[Error] The document type of document '+updates['_id']+' is not '+doctype)
                updates = {}
                continue
            
            # first ensure that all original properties are copied, so an update does not result in lost data!
            for prop in original_document.keys():
                if not prop in updates:
                    updates[prop] = original_document[prop]
            
            # now start changing what needs to be changed
            for prop in updates.keys():
                if prop not in original_document:
                    pass # this is fine, will happen e.g. when adding a status code or content_length for the first time
                else:
                    if not type(original_document[prop]) is type(updates[prop]):
                        print(type(original_document[prop]))
                        print('[Error] The updated property '+prop+' doesn\'t have the right type. Cannot update '+updates['_id'])
                        updates = {}
                        continue
                    # if it's a list, make sure the update values are appended to the existing fields
                    if type(original_document[prop]) is list:
                        new_list = original_document[prop]
                        for val in updates[prop]:
                            if val not in new_list:
                                new_list.append(val)

                        # filter out empty values
                        updates[prop] = list(filter(None, new_list))
                        
                    # if it's a dict, make sure the update values are added to the existing map
                    # for example, this is the case when updating tags of a document
                    if type(original_document[prop]) is dict:
                        new_dict = original_document[prop]
                        for key in updates[prop]:
                            new_dict[key] = updates[prop][key]
                        
                        # filter out empty values
                        updates[prop] = {x: new_dict[x] for x in new_dict if new_dict[x] and len(new_dict[x]) > 0}
                                
        
        # now bulk update all documents with changes!
        r = self.requests_session.post(
            self.BBRF_API+'/_bulk_docs',
            json.dumps({'docs': to_be_updated}),
            headers={"Authorization": self.auth, 'Content-Type': 'application/json'}
        )
        if 'error' in r.json():
            raise Exception(r.json()['error'])
            
        return [x['_id'] for x in to_be_updated]
        
    '''
    return true if docs are identical, false if there are differences
    '''
    def docs_are_equal(self, current, updated, ignore = ['_id', '_rev', 'program', 'type'], check_lists = True):
        
        current = {k: current[k] for k in current if k not in ignore}
        updated = {k: updated[k] for k in updated if k not in ignore}
        
        if current == updated:
            return True
        
        # if documents are not equal and check_lists is set, we will also consider
        # documents equal if the elements of the update list are already in the current list
        if check_lists:
            current_nolists = {k: current[k] for k in current if k not in ignore and not type(current[k]) is list}
            updated_nolists = {k: updated[k] for k in updated if k not in ignore and not type(updated[k]) is list}
            
            # if even without the lists they are still different, don't bother to check the lists
            if not current_nolists == updated_nolists:
                return False
            else:
                update_lists = {k: updated[k] for k in updated if k not in ignore and type(updated[k]) is list}
                for lst in update_lists:
                    for l in update_lists[lst]:
                        if not l in current[lst]:
                            return False
                
                return True
        
        return False
        
    '''
    Inspired by https://github.com/dpavlin/angular-mojolicious/edit/master/couchdb-changes.pl
    
    Will handle changes in batches of 10 seconds at a time.
    '''
    def listen_for_changes(self):
        import time
        
        url = self.BBRF_API+'/_changes?feed=continuous;include_docs=true;since='
        error = None
        seq = 'now'
        change_data = []
        last_update = 0
        
        while not error:
            with self.requests_session.get(url+seq, timeout=90, headers={"Authorization": self.auth}, stream=True) as resp:
                for chunk in resp.iter_content(None):
                    if chunk:  # filter out keep-alive new chunks
                        chunk = chunk.decode("utf-8")
                        changes = chunk.split('\n')  # make sure we handle individual changes
                        for change in changes:
                            print(change)
                            if(change.startswith('{')):
                                data = json.loads(change)
                                change_data.append(data)
                                # handle changes in batches of 10 seconds
                                # to avoid cluttering the HTTP pipeline
                                if last_update < time.time() - 10:
                                    error, seq = self.handle_changes(change_data, seq)
                                    change_data = []
                                    last_update = time.time()
    
    '''
    Handle a batch of changes by sending a Slack notification if it
    concerns a new document.
    
    @todo trigger a list of agents when new inscope has been added
    @todo trigger actions for every new domain
    @todo trigger actions for every new ip
    @todo trigger actions for every new url
    '''
    def handle_changes(self, changes, seq):
        error = None
        source = ''
        message = ''
        
        print('Looping changes')
        for change in changes:
            if 'error' in change:
                error = change['error']
            elif 'last_seq' in change:
                seq = change['last_seq']
            elif 'changes' in change:
                seq = change['seq']
                if change['changes'][-1]['rev'].startswith('1-'):  # check if it is the first revision of a document
                    # notify on new domain
                    if 'type' in change['doc'] and change['doc']['type'] == 'domain':
                        if 'source' in change['doc']:
                            message += '['+change['doc']['source']+'] '
                        message += change['id'] + ' was added\n'
                        
                    # also notify when a new notification was added
                    if 'type' in change['doc'] and change['doc']['type'] == 'alert':
                        message += '[ALERT] '
                        if 'source' in change['doc'] and change['doc']['source']:
                            message += '['+change['doc']['source']+'] '
                        message += change['doc']['message']
        
        if message:
            if self.sc:
                self.sc.api_call('chat.postMessage', channel='bbrf', text=message, username='bbrf-bot')
            if self.discord_webhook:
                requests.post(self.discord_webhook, json.dumps({'content': message}), headers={'Content-Type': 'application/json'})
        
        return error, seq
    
    '''
    Run an agent by triggering the Lambda HTTP endpoint for an agent
    
    @todo - should the invocation be run asynchronously?
    '''
    def run_agent(self, agent_name, program_name):
        r = self.requests_session.get(self.BBRF_API+'/agents_api_gateway', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        gateway = r.json()['url']
        
        return requests.get(gateway+agent_name+'?program='+program_name).text
    
    '''
    Configure the gateway URL
    '''
    def set_agent_gateway(self, url):
        # see if it exists
        gateway = self.get_document('agents_api_gateway')
        if gateway:
            self.update_document('config', 'agents_api_gateway', {'url': url})
        else:
            self.requests_session.put(self.BBRF_API+'/agents_api_gateway', json.dumps({'doctype': 'config', 'url': url}), headers={"Authorization": self.auth})

    '''
    Register a new agent to the database
    '''
    def create_new_agent(self, agent_name):
        if not agent_name:
            return
        else:
            agent = {"type": "agent", "name": agent_name}
            r = self.requests_session.put(self.BBRF_API+'/agent_'+agent_name, json.dumps(agent), headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
    
    '''
    Push an alert into the DB
    '''
    def create_alert(self, alert_message, program_name, source_name):
        if type(alert_message) is list:
            alert_message = '\n'.join(alert_message)
        alert = {
            "type": "alert",
            "program": program_name,
            "message": alert_message,
            "source": source_name
        }
        r = self.requests_session.post(self.BBRF_API, json.dumps(alert), headers={"Content-Type": "application/json", "Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        
    '''
    List scopes across programs using _view/scope - does not support filtering by program.
    To get scope for one program, use `bbrf program scope`.
    '''
    def get_scope(self, in_out="in", active_inactive="active"):
        
        r  = None
        
        # list inscope of active programs
        if in_out == "in" and active_inactive == "active":
            r = self.requests_session.get(
                self.BBRF_API+'/_design/bbrf/_view/scope?startkey=[true,"IN"]&endkey=[true,"INZZZ"]',
                headers={"Authorization": self.auth}
            )
        
        # list inscope of inactive programs
        if in_out == "in" and active_inactive == "inactive":
            r = self.requests_session.get(
                self.BBRF_API+'/_design/bbrf/_view/scope?startkey=[false,"IN"]&endkey=[false,"INZZZ"]',
                headers={"Authorization": self.auth}
            )
            
        # list outscope of active programs
        if in_out == "out" and active_inactive == "active":
            r = self.requests_session.get(
                self.BBRF_API+'/_design/bbrf/_view/scope?startkey=[true,"OUT"]&endkey=[true,"OUTZZZ"]',
                headers={"Authorization": self.auth}
            )
            
        # list outscope of inactive programs
        if in_out == "out" and active_inactive == "inactive":
            r = self.requests_session.get(
                self.BBRF_API+'/_design/bbrf/_view/scope?startkey=[false,"OUT"]&endkey=[false,"OUTZZZ"]',
                headers={"Authorization": self.auth}
            )
        
        return [r['key'][2] for r in r.json()['rows']]
    
    '''
    Get a list of documents based on a search term by tags, filtered by doctype
    '''
    def search_tags(self, key, value, doctype = None, program = None):
        if doctype and doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/search_tags?key=["'+key+'", "'+value+'"]', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
            
        results = r.json()['rows']
        
        # filter results based on the doctype and program name
        if(doctype):
            results = [x for x in results if x['value'][0] == doctype]
        if(program):
            results = [x for x in results if x['value'][2] == program]
        
        return [x['value'][1] for x in results]
    

    '''
    Get a list of documents based on a search term by tags, filtered by doctype
    '''
    def search_tags_between(self, key, value, before_after, doctype = None, program = None):
        if doctype and doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        if before_after == 'before':
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/search_tags?startkey=["'+key+'"]&endkey=["'+key+'","'+value+'"]', headers={"Authorization": self.auth})
        elif before_after == 'after':
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/search_tags?startkey=["'+key+'","'+value+'"]&endkey=["'+key+'ZZZZZ"]&', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
            
        results = r.json()['rows']
        
        # filter results based on the doctype and program name
        if(doctype):
            results = [x for x in results if x['value'][0] == doctype]
        if(program):
            results = [x for x in results if x['value'][2] == program]
        
        return [x['value'][1] for x in results]