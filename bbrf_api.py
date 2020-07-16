import requests
import base64
import json
from slackclient import SlackClient


class BBRFApi:
    BBRF_API = None
    auth = None
    doctypes = ['ip', 'domain', 'program', 'task']
    sc = None
    
    requests_session = None
    
    def __init__(self, couchdb_url, user, pwd, slack_token):
        auth = user+':'+pwd
        self.auth = 'Basic '+base64.b64encode(auth.encode('utf-8')).decode('utf-8')
        self.requests_session = requests.Session()
        if slack_token:
            self.sc = SlackClient(slack_token)
        self.BBRF_API = couchdb_url
    
    '''
    Create a new program.
    '''
    def create_new_program(self, program_name=None, disabled=False, passive_only=False):
        if not program_name:
            return
        else:
            program = {"type": "program", "disabled": disabled, "passive_only": passive_only, "inscope": [], "outscope": []}
            r = self.requests_session.put(self.BBRF_API+'/'+program_name, json.dumps(program), headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
    
    '''
    Get a list of all domains, filtered by program name if provided.
    
    @todo: generalize this and get_ips by general function get_document_by_program_name with additional paramter doctype
    '''
    def get_domains_by_program_name(self, program_name=None):
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/domains?key="'+program_name+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/domains', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    '''
    Get all documents of a certain type
    '''
    def get_documents(self, doctype, program_name = None):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        if doctype is "task":
            return self.get_tasks()
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s?key="'+program_name+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        print(r.json())
        return [r['value'] for r in r.json()['rows']]
    
    '''
    @todo put restrictions on 'view' parameter, should only allow lowercase and _
    '''
    def get_documents_view(self, program_name, doctype, view):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s_'+view+'?key="'+program_name+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s_'+view, headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    '''
    Get a list of all ips, filtered by program name if provided.
    '''
    def get_ips_by_program_name(self, program_name=None):
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/ips?key="'+program_name+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/ips', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    '''
    Get a list of all programs.
    '''
    def get_programs(self):
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/programs', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['key'] for r in r.json()['rows']]
    
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
    Get a list of all tasks.
    '''
    def get_tasks(self):
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/tasks', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return r.json()['rows']
    
    '''
    Register a new task.
    '''
    def register_task(self, name):
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/tasks', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        return [r['key'] for r in r.json()['rows']]
    
    '''
    Add a list of documents to a program in bulk.
    '''
    def add_documents(self, doctype, identifiers, program_name, source=None):
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
                
            if source:
                doc['source'] = source
            bulk['docs'].append(doc)
        
        r = self.requests_session.post(
            self.BBRF_API+'/_bulk_docs', json.dumps(bulk),
            headers={"Authorization": self.auth, "Content-Type": "application/json"}
        )
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        
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
            print(document)
            
        # Need to encode the document so it can handle CIDR ranges including /
        r = self.requests_session.get(self.BBRF_API+'/'+requests.utils.quote(document, safe=''), headers={"Authorization": self.auth})
        print(r.json())
        if 'error' in r.json() and r.json()['error'] != 'not_found':
            raise Exception(r.json()['error'])
        elif 'error' in r.json() and r.json()['error'] == 'not_found':
            print("here3")
            return
        if 'type' in r.json() and not r.json()['type'] == doctype:
            raise Exception('The specified document (type: '+r.json()['type']+') is not of the requested type '+doctype)
            print("here4")
        if '_rev' in r.json():
            r = self.requests_session.delete(self.BBRF_API+'/'+requests.utils.quote(document, safe='')+'?rev='+r.json()['_rev'], headers={"Authorization": self.auth})
            if 'error' in r.json() and r.json()['error'] != 'not_found':
                raise Exception(r.json()['error'])
                
    '''
    Return a raw version of a document by id
    '''
    def get_document(self, docid):
        r = self.requests_session.get(self.BBRF_API+'/'+docid, headers={"Authorization": self.auth})
        if 'error' in r.json() and r.json()['error'] == 'not_found':
            return
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
                    original_document[prop] = []  # initiate the property list if it doesn't exist
                elif not type(original_document[prop]) is list:
                    print('The updated key is not a list. Cannot append data to '+prop)
                    continue
                for val in updates[prop]:
                    if val not in original_document[prop]:
                        document_changed = True
                        original_document[prop].append(val)
                        
                # filter out empty values
                original_document[prop] = list(filter(None, original_document[prop]))
            
            if document_changed:
                r = self.requests_session.put(
                    self.BBRF_API+'/'+requests.utils.quote(document, safe='')+'?rev='+r.json()['_rev'],
                    json.dumps(original_document),
                    headers={"Authorization": self.auth, "Content-Type": "application/json"}
                )
                if 'error' in r.json():
                    raise Exception(r.json()['error'])
                
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
            with requests.get(url+seq, timeout=90, headers={"Authorization": self.auth}, stream=True) as resp:
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
    
    @todo trigger a list of tasks when new inscope has been added
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
                        if 'source' in change['doc']:
                            message += '['+change['doc']['source']+'] '
                        message += change['doc']['message']
        
        if message:
            print(self.sc.api_call('chat.postMessage', channel='bbrf', text=message, username='bbrf-bot'))
        
        return error, seq
    
    '''
    Run a task by triggering the Lambda HTTP endpoint for a task
    
    @todo - should the invocation be run asynchronously?
    '''
    def run_task(self, task_name, program_name):
        r = self.requests_session.get(self.BBRF_API+'/agents_api_gateway', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception(r.json()['error'])
        gateway = r.json()['url']
        
        return requests.get(gateway+task_name+'?program='+program_name).text
    
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