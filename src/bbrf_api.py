import requests
import base64
import json
from slack_sdk import WebClient
import logging

class BBRFApi:
    BBRF_API = None
    auth = None
    doctypes = ['ip', 'domain', 'program', 'agent', 'url', 'service', 'config', 'alert']
    sc = None
    slack_channel = None
    discord_webhook = None
    slack_webhook = None
    do_debug = False
    requests_session = None
    
    def __init__(self, couchdb_url, user, pwd, slack_token = None, discord_webhook = None, slack_webhook = None, slack_channel = None, ignore_ssl_errors = False, debug = False):
        auth = user+':'+pwd
        self.auth = 'Basic '+base64.b64encode(auth.encode('utf-8')).decode('utf-8')
        self.requests_session = requests.Session()
        self.do_debug = debug
        if debug:
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True
        if slack_token:
            self.sc = WebClient(token=slack_token)
        if slack_channel:
            self.slack_channel = slack_channel
        if discord_webhook:
            self.discord_webhook = discord_webhook
        if slack_webhook:
            self.slack_webhook = slack_webhook
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
                program['tags'] = self.process_tags(tags)
            r = self.requests_session.put(self.BBRF_API+'/'+requests.utils.quote(program_name, safe=''), json.dumps(program), headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
    
    '''
    Get a list of all domains, filtered by program name if provided.
    
    @todo: generalize this and get_ips by general function get_document_by_program_name with additional paramter doctype
    '''
    def get_domains_by_program_name(self, program_name=None, show_disabled=False):
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/domains?reduce=false&key="'+requests.utils.quote(program_name, safe='')+'"', headers={"Authorization": self.auth})
            return [r['value'] for r in r.json()['rows']]
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/domains?reduce=false', headers={"Authorization": self.auth})
            # by default, filter out all disabled programs - sadly this needs to happen client side;
            # because there is no relational link between a domain and its program to look up the status of 
            # the program when indexing.
            # Actually, this can probably be improved with custom queries:
            # `https://docs.couchdb.org/en/stable/api/database/find.html`
            if show_disabled:
                # no filter, so return everything
                return [r['value'] for r in r.json()['rows']]
            else:
                active_programs = self.get_programs(show_disabled=show_disabled)
                return [r['value'] for r in r.json()['rows'] if r['key'] in active_programs]
            
    
    '''
    Get a list of all urls, filtered by program or hostname if provided.
    '''
    def get_urls_by_hostname(self, hostname=None, with_query=False, root_only=False):
        if hostname:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/urls_by_hostname?reduce=false&key="'+hostname+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/urls_by_hostname?reduce=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        # print all url, status, content_length if status and content length are set    
        return self.process_urls(r.json()['rows'], with_query, root_only)
    
    def get_urls_by_program(self, program=None, with_query=False, root_only=False, show_disabled=False):
        if program:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/urls_by_program?reduce=false&key="'+requests.utils.quote(program, safe='')+'"', headers={"Authorization": self.auth})
            return self.process_urls(r.json()['rows'], with_query, root_only)
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/urls_by_program?reduce=false', headers={"Authorization": self.auth})
            if show_disabled:
                # no filter, so return everything
                return self.process_urls(r.json()['rows'], with_query)
            else:
                active_programs = self.get_programs(show_disabled=show_disabled)
                return self.process_urls([x for x in r.json()['rows'] if x['key'] in active_programs], with_query, root_only)        
        
    def process_urls(self, urls, with_query=False, root_only=False):
        if not with_query:
            if not root_only:
            # print all url, status, content_length if status and content length are set
                return [" ".join([str(x) for x in r['value'][:3] if x]) for r in urls]
            else:
            # print only roots or urls:
                return list(set(['/'.join(r['value'][0].split('/',3)[:3]) for r in urls]))
        else:
            # get a list of URLs without any queries
            no_query = [" ".join([str(x) for x in r['value'][:3] if x]) for r in urls if len(r['value'][3]) == 0]
            # expand the URLs that do have queries
            expanded = [ [url['value'][0]+'?'+q] + url['value'][1:3] for url in urls for q in url['value'][3] if q]
            return [" ".join([str(x) for x in r[:3] if x]) for r in expanded] + no_query
    
    '''
    Get a list of all services, filtered by program name if provided.
    '''
    def get_services_by_program_name(self, program_name=None, show_disabled=False):
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/services?reduce=false&key="'+requests.utils.quote(program_name, safe='')+'"', headers={"Authorization": self.auth})
            return [r['value'] for r in r.json()['rows']]
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/services?reduce=false', headers={"Authorization": self.auth})
            if show_disabled:
                # no filter, so return everything
                return [r['value'] for r in r.json()['rows']]
            else:
                active_programs = self.get_programs(show_disabled=show_disabled)
                return [r['value'] for r in r.json()['rows'] if r['key'] in active_programs]
    
    '''
    Get all documents of a certain type
    '''
    def get_documents_of_type(self, doctype, program_name = None):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        if doctype == 'agent':
            return self.get_agents()
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s?reduce=false&key="'+requests.utils.quote(program_name, safe='')+'"', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s?reduce=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        return [r['value'] for r in r.json()['rows']]
    
    '''
    @todo put restrictions on 'view' parameter, should only allow lowercase and _
    '''
    def get_documents_view(self, program_name, doctype, view, show_disabled=False):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s_'+view+'?reduce=false&key="'+requests.utils.quote(program_name, safe='')+'"', headers={"Authorization": self.auth})
            return [r['value'] for r in r.json()['rows']]
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/'+doctype+'s_'+view+'?reduce=false', headers={"Authorization": self.auth})
            if show_disabled:
                # no filter, so return everything
                return [r['value'] for r in r.json()['rows']]
            else:
                active_programs = self.get_programs(show_disabled=show_disabled)
                return [r['value'] for r in r.json()['rows'] if r['key'] in active_programs]
    
    '''
    Get a list of all ips, filtered by program name if provided.
    '''
    def get_ips_by_program_name(self, program_name=None, filter_cdn=False, show_disabled=False):
        
        cdn_filter = '_no_cdn' if filter_cdn else ''
        
        if program_name:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/ips'+cdn_filter+'?reduce=false&key="'+requests.utils.quote(program_name, safe='')+'"', headers={"Authorization": self.auth})
            return [r['value'] for r in r.json()['rows']]
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/ips'+cdn_filter+'?reduce=false', headers={"Authorization": self.auth})
            # by default, filter out all disabled programs
            if show_disabled:
                return [r['value'] for r in r.json()['rows']]
            else:
                active_programs = self.get_programs(show_disabled=show_disabled)
                return [r['value'] for r in r.json()['rows'] if r['key'] in active_programs]
    
    '''
    Get a list of all programs.
    '''
    def get_programs(self, show_disabled=False, show_empty_scope=False):
        if show_disabled:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/programs?reduce=false', headers={"Authorization": self.auth})
        else:
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/programs?reduce=false&key=false', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        
        try:
            if show_empty_scope:
                return [r['id'] for r in r.json()['rows']]
            else:
                return [r['id'] for r in r.json()['rows'] if r['value'] > 0]
        except:
            print('[WARNING] Your BBRF server views are deprecated, it is strongly recommended to upgrade. Run `bbrf server upgrade` to upgrade.')
            return [r['value'] for r in r.json()['rows']]
    
    def get_program_scope(self, program_name):
        if program_name == '@INFER':
            return None, [], []
        self.debug('getting program scope')
        r = self.requests_session.get(self.BBRF_API+'/'+requests.utils.quote(program_name, safe=''), headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        return r.json(), r.json()['inscope'], r.json()['outscope']
    
    def update_program_scope(self, program_name, inscope, outscope, program=None):
        self.debug('updating program scope')
        if not program:
            r = self.requests_session.get(self.BBRF_API+'/'+requests.utils.quote(program_name, safe=''), headers={"Authorization": self.auth})
            if 'error' in r.json():
                raise Exception('BBRF server error: '+r.json()['error'])
            program = r.json()
        # only update if different!
        if program['inscope'] != inscope or program['outscope'] != outscope:
            program['inscope'] = inscope
            program['outscope'] = outscope
            r = self.requests_session.put(self.BBRF_API+'/'+requests.utils.quote(program_name, safe='')+'?rev='+program['_rev'], json.dumps(program), headers={"Authorization": self.auth})
            if 'error' in r.json():
                raise Exception('BBRF server error: '+r.json()['error'])
            
    def get_program_blacklist(self, program_name=None, doc=None):
        self.debug('getting program blacklist')
        if program_name == '@INFER':
            return []
        if not doc:
            r = self.requests_session.get(self.BBRF_API+'/'+requests.utils.quote(program_name, safe=''), headers={"Authorization": self.auth})
            doc = r.json()
        if 'error' in doc:
            raise Exception('BBRF server error: '+r.json()['error'])
        if 'blacklist' not in doc:
            return []
        return doc['blacklist']
    
    def update_program_blacklist(self, program_name, blacklist):
        self.debug('updating program blacklist')
        r = self.requests_session.get(self.BBRF_API+'/'+requests.utils.quote(program_name, safe=''), headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        program = r.json()
        program['blacklist'] = blacklist
        r = self.requests_session.put(self.BBRF_API+'/'+requests.utils.quote(program_name, safe='')+'?rev='+program['_rev'], json.dumps(program), headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        
    '''
    Return all document identifiers of documents belonging to a program.
    '''
    def get_all_program_documents(self, program_name):
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/program_all_documents?key="'+requests.utils.quote(program_name, safe='')+'"', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        return [ (r['id'], r['value']) for r in r.json()['rows'] ]
            
    '''
    Get a list of all agents.
    '''
    def get_agents(self):
        self.debug('getting agents')
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/agents', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        return r.json()['rows']
    
    '''
    Register a new agent.
    '''
    def register_agent(self, name):
        self.debug('registering agent')
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/agents', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        return [r['key'] for r in r.json()['rows']]
    
    '''
    Add a list of documents to a program in bulk.
    '''
    def add_documents(self, doctype, identifiers, program_name, source=None, tags=[]):
        self.debug('adding documents in bulk')
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
        
        if program_name == '@INFER':
            # When related identifiers are supplied, e.g. `bbrf ip add 1.1.1.1:example.com`
            # we can infer the program by fetching the program for `example.com`
            
            program_candidates = {}
            
            if relname:
                # get all candidate program names by identifier in rel:
                r = self.requests_session.post(self.BBRF_API+'/_all_docs?include_docs=true', json.dumps({'keys': [x for docid in identifiers.keys() for x in identifiers[docid]]}), headers={"Authorization": self.auth, 'Content-Type': 'application/json'})
                program_candidates = {a['key']: a['doc']['program'] for a in r.json()['rows'] if 'doc' in a and a['doc']}
            
            # get all scope definitions of programs to dynamically match domains
            r = self.requests_session.post(self.BBRF_API+'/_all_docs?include_docs=true', json.dumps({'keys': [x for x in self.get_programs()]}), headers={"Authorization": self.auth, 'Content-Type': 'application/json'})
            program_scopes = {r['id']: {'in': r['doc']['inscope'], 'out':r['doc']['outscope']}  for r in r.json()['rows'] if 'doc' in r and r['doc']}
        
        for docid in identifiers.keys():
            # extract the appropriate program name from the list of candidates
            infered_program_name = program_name
            if program_name == '@INFER':
                infered_program_name = [program_candidates[d] for d in program_candidates.keys() if d in identifiers[docid]]
                if len(infered_program_name) > 0:
                    infered_program_name = infered_program_name[0]
                else:
                    # no luck with the linked documents, but if we're adding a URL or domain,
                    # we may match against known scopes
                    if doctype == 'domain':
                        from . import BBRFClient
                        infered_program_name = [p for p in program_scopes.keys() if BBRFClient.matches_scope(docid, program_scopes[p]['in']) and not BBRFClient.matches_scope(docid, program_scopes[p]['out'])]
                        if len(infered_program_name) > 0:
                            infered_program_name = infered_program_name[0]
                    elif doctype == 'url':
                        from . import BBRFClient
                        infered_program_name = [p for p in program_scopes.keys() if BBRFClient.matches_scope(identifiers[docid]['hostname'], program_scopes[p]['in']) and not BBRFClient.matches_scope(identifiers[docid]['hostname'], program_scopes[p]['out'])]
                        if len(infered_program_name) > 0:
                            infered_program_name = infered_program_name[0]

            if not infered_program_name or infered_program_name == '@INFER':
                # was unable to infer, skipping document
                continue
                    
            doc = {
                '_id': docid,
                'program': infered_program_name,
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
                doc['tags'] = self.process_tags(tags)
                
            bulk['docs'].append(doc)
        
        r = self.requests_session.post(
            self.BBRF_API+'/_bulk_docs', json.dumps(bulk),
            headers={"Authorization": self.auth, "Content-Type": "application/json"}
        )
        
        if 'error' in r.json():
            raise Exception('Unexpected BBRF response: '+r.json()['error'])
        
        # return (success,failed) with identifiers of new docs and docs that failed due to conflict
        return (
            [doc['id'] for doc in r.json() if 'ok' in doc and doc['ok']],
            [doc['id'] for doc in r.json() if 'error' in doc and doc['error'] == 'conflict']
        )
        
        
    
    '''
    Get the identifier of a document based on a set of properties defined in propmap
    '''
    def get_document_id_by_properties(self, doctype, propmap):
        if doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        docs = self.get_documents_of_type(doctype)
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
        if 'error' in r.json() and r.json()['error'] != 'not_found':
            raise Exception('BBRF server error: '+r.json()['error'])
        elif 'error' in r.json() and r.json()['error'] == 'not_found':
            return
        if 'type' in r.json() and not r.json()['type'] == doctype:
            raise Exception('The specified document (type: '+r.json()['type']+') is not of the requested type '+doctype)
        if '_rev' in r.json():
            r = self.requests_session.delete(self.BBRF_API+'/'+requests.utils.quote(document, safe='')+'?rev='+r.json()['_rev'], headers={"Authorization": self.auth})
            if 'error' in r.json() and r.json()['error'] != 'not_found':
                raise Exception('BBRF server error: '+r.json()['error'])
                
    '''
    Return a raw version of a document by id
    '''
    def get_document(self, docid):
        # escape leading underscores
        if docid.startswith('_'):
            docid = '.'+docid
        r = self.requests_session.get(self.BBRF_API+'/'+requests.utils.quote(docid, safe=''), headers={"Authorization": self.auth})
        if 'error' in r.json() and r.json()['error'] == 'not_found':
            return None
        return r.text
    
    '''
    Return a JSON of many documents by id
    '''
    def get_documents(self, docids):
        
        r = self.requests_session.post(self.BBRF_API+'/_all_docs?include_docs=true', json.dumps({'keys': [x if not x.startswith('_.') else '.'+x for x in docids]}), headers={"Authorization": self.auth, 'Content-Type': 'application/json'})
        
        if 'error' in r.json() and r.json()['error'] == 'not_found':
            return None
        return json.dumps([ x['doc'] for x in r.json()['rows'] if not 'error' in x ])
        
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
            raise Exception('BBRF server error: '+r.json()['error'])
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
                    raise Exception('BBRF server error: '+r.json()['error'])
                
                return document
        
    '''
    Update documents in bulk
    The provided batch_updates need to be a dict of updates mapping the id to the dict of updates
    '''
    def update_documents(self, doctype, batch_updates, append_tags=False):
        self.debug('updating documents in bulk')
        # first, get the latest revisions of each of the listed documents
        r = self.requests_session.post(self.BBRF_API+'/_all_docs?include_docs=true', json.dumps({'keys': [x for x in batch_updates.keys()]}), headers={"Authorization": self.auth, 'Content-Type': 'application/json'})
        
        current = {a['key']: a['doc'] for a in r.json()['rows'] if 'doc' in a and a['doc']}
        updates = {x['key']: batch_updates[x['key']].update({'_id': x['key'], '_rev':x['value']['rev']}) or batch_updates[x['key']] for x in r.json()['rows'] if 'doc' in x and x['doc']}
        
        to_be_updated = []
        
        for x in current.keys():
            # we need to ensure the source property is preserved when it's not explicitly set
            if not 'source' in updates[x] and 'source' in current[x]:
                updates[x]['source'] = current[x]['source']
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
                    elif type(original_document[prop]) is dict:
                        new_dict = original_document[prop]
                        for key in updates[prop]:
                            if prop == 'tags' and append_tags:
                                # append the new value or list to the existing list
                                if not key in new_dict:
                                    new_dict[key] = updates[prop][key]
                                elif type(new_dict[key]) is list:
                                    new_dict[key].extend(updates[prop][key] if type(updates[prop][key]) is list else [updates[prop][key]])
                                else: # already existed with a single value
                                    updates[prop][key] = updates[prop][key] if type(updates[prop][key]) is list else [updates[prop][key]]
                                    updates[prop][key].extend([new_dict[key]])
                                    new_dict[key] = updates[prop][key]
                                # remove duplicates
                                if type(new_dict[key]) is list:
                                    new_dict[key] = list(set(new_dict[key]))
                            else:
                                # overwrite whatever values we have with the new value or list
                                new_dict[key] = updates[prop][key]
                        
                        # filter out empty values
                        updates[prop] = {x: new_dict[x] for x in new_dict if new_dict[x] and len(new_dict[x]) > 0}
                                
        
        # now bulk update all documents with changes!
        if len(to_be_updated) > 0:
            r = self.requests_session.post(
                self.BBRF_API+'/_bulk_docs',
                json.dumps({'docs': to_be_updated}),
                headers={"Authorization": self.auth, 'Content-Type': 'application/json'}
            )
            if 'error' in r.json():
                raise Exception('BBRF server error: '+r.json()['error'])

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
                try:
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
                except requests.exceptions.ChunkedEncodingError as e:
                    # this sometimes occurs with the new nginx proxy
                    # in front of the couchdb server when the response
                    # remains empty and the in-between proxy times out?
                    # luckily it seems we can just continue polling to keep
                    # this working as intended.
                    pass

    
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

        # keep track of new documents to trigger hooks in bulk
        new = {'domain': [], 'ip': [], 'service': [], 'url': []}
        update = {'domain': [], 'ip': [], 'service': [], 'url': []}
        
        print('Looping changes')
        for change in changes:
            if 'error' in change:
                error = change['error']
            elif 'last_seq' in change:
                seq = change['last_seq']
            elif 'changes' in change:
                seq = change['seq']
                if change['changes'][-1]['rev'].startswith('1-'):  # check if it is the first revision of a document
                    
                    if 'type' in change['doc'] and change['doc']['type'] in new.keys():
                        new[change['doc']['type']].append(change['id'])
                    
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
                else:
                    # it's not new, hence it's an updated document:
                    if 'type' in change['doc'] and change['doc']['type'] in new.keys():
                        update[change['doc']['type']].append(change['id'])
        
        if message:
            if self.sc:
                try:
                    self.sc.chat_postMessage(channel=self.slack_channel, text=message)
                except Exception as e:
                    print('[ERROR] '+e.response['error'])
            if self.discord_webhook:
                requests.post(self.discord_webhook, json.dumps({'content': message}), headers={'Content-Type': 'application/json'})
            if self.slack_webhook:
                requests.post(self.slack_webhook, json.dumps({'text': message}), headers={'Content-Type': 'application/json'})
                
        for doctype in new.keys():
            if len(new[doctype]) > 0:
                self.execute_hooks('new', doctype, new[doctype])
        for doctype in update.keys():
            if len(update[doctype]) > 0:
                self.execute_hooks('update', doctype, update[doctype])
        
        return error, seq
    
    '''
    Execute hooks in ~/.bbrf/hooks/{domain,ip,url,service}/{new,update}/
    '''
    def execute_hooks(self, hooktype, doctype, identifiers):
        print('Executing '+hooktype+'_'+doctype)
        # first iteration without queueing: just
        # run the programs all at once in the background
        from subprocess import Popen
        from os import listdir
        from os.path import isfile, join, expanduser
        hookdir = expanduser('~/.bbrf/hooks/'+doctype+'/'+hooktype+'/')
        try:
            scripts = [join(hookdir, f) for f in listdir(hookdir) if isfile(join(hookdir, f)) and f.endswith('.sh')]
            for script in scripts:
                print('Running '+script+'...')
                args = [script]
                args.extend(identifiers)
                p = Popen(args)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(e.message)
            # possibly the hooks directory doesn't exist
            pass
        #p = Popen([, 'ls'])
    
    '''
    Run an agent by triggering the Lambda HTTP endpoint for an agent
    
    @todo - should the invocation be run asynchronously?
    '''
    def run_agent(self, agent_name, program_name):
        r = self.requests_session.get(self.BBRF_API+'/agents_api_gateway', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
        gateway = r.json()['url']
        
        return requests.get(gateway+agent_name+'?program='+requests.utils.quote(program_name, safe='')).text
    
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
            raise Exception('BBRF server error: '+r.json()['error'])
    
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
            "_id": alert_message,
            "source": source_name
        }
        r = self.requests_session.post(self.BBRF_API, json.dumps(alert), headers={"Content-Type": "application/json", "Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
            
    '''
    List scopes across programs using _view/scope - does not support filtering by program.
    To get scope for one program, use `bbrf program scope`.
    '''
    def get_scopes(self, show_disabled=False):
        r = self.requests_session.get(
            self.BBRF_API+'/_design/bbrf/_view/scope',
            headers={"Authorization": self.auth}
        )
        results = [ r for r in r.json()['rows'] if show_disabled or r['key'][0] ]
        return [r['key'][2] for r in results if r['key'][1].lower() == "in"], [r['key'][2] for r in results if r['key'][1].lower() == "out"]
        
    '''
    Get a list of documents based on a search term by tags, filtered by doctype
    '''
    def search_tags(self, key, value, doctype = None, program = None, show_disabled=False , show_empty_scope=False):
        if doctype and doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/search_tags?key=["'+requests.utils.quote(key, safe='')+'", "'+requests.utils.quote(value, safe='')+'"]', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
            
        results = r.json()['rows']
        
        # filter results based on the doctype and program name
        if doctype:
            results = [x for x in results if x['value'][0] == doctype]
        # restrict further if needs to match a specific program
        if not doctype == 'program' and program:
            results = [x for x in results if x['value'][2] == program]
        # remove disabled programs unles the --show-disabled flag is set
        if not show_disabled and doctype == 'program':
            active_programs = self.get_programs(show_disabled=show_disabled, show_empty_scope=show_empty_scope)
            results = [x for x in results if x['value'][2] in active_programs]
        
        return list(set([x['value'][1] for x in results if x['key'][0] == key]))
    

    def process_tags(self, tags, append_tags=False):
        '''
        Process a list of -t <name:value>... and return 
        as a dict of scalars or arrays.
        '''
        tagmap = {}
        for x in tags:
            k, v = x.split(':', 1)
            if k not in tagmap:
                tagmap[k] = v if not append_tags else [v]
            else:
                if type(tagmap[k]) is list:
                    tagmap[k].extend([v])
                else:
                    tagmap[k] = [v, tagmap[k]]
        return tagmap
    
    '''
    Get a list of documents based on a search term by tags, filtered by doctype
    '''
    def search_tags_between(self, key, value, before_after, doctype = None, program = None, show_disabled=False, show_empty_scope=False):
        if doctype and doctype not in self.doctypes:
            raise Exception('This doctype is not supported')
        if before_after == 'before':
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/search_tags?startkey=["'+requests.utils.quote(key, safe='')+'"]&endkey=["'+requests.utils.quote(key, safe='')+'","'+requests.utils.quote(value, safe='')+'"]', headers={"Authorization": self.auth})
        elif before_after == 'after':
            r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/search_tags?startkey=["'+requests.utils.quote(key, safe='')+'","'+requests.utils.quote(value, safe='')+'"]&endkey=["'+key+'ZZZZZ"]&', headers={"Authorization": self.auth})
        if 'error' in r.json():
            raise Exception('BBRF server error: '+r.json()['error'])
            
        results = r.json()['rows']
        
        # filter results based on the doctype and program name
        if doctype:
            results = [x for x in results if x['value'][0] == doctype]
        if not doctype == 'program' and program:
            results = [x for x in results if x['value'][2] == program]
        if not show_disabled:
            active_programs = self.get_programs(show_disabled=show_disabled, show_empty_scope=show_empty_scope)
            results = [x for x in results if x['value'][2] in active_programs]
        
        return list(set([x['value'][1] for x in results if x['key'][0] == key]))
    
    def get_tags(self, tagname, program_name=None):
        filter_name = 'key="'+requests.utils.quote(tagname, safe='')+'"' if tagname else ''
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf/_view/tags?'+filter_name, headers={"Authorization": self.auth})
        results = r.json()['rows']
        
        if tagname:
            return [x['value'][0]+' '+x['value'][1] for x in results if not(not(program_name)) == (x['value'][2] == program_name)]
        else:
            return set([x['key'] for x in results if not(not(program_name)) == (x['value'][2] == program_name)])
    
    def server_upgrade(self, admin, password):
        '''
        Upgrade server to the latest views and ensure access rights are correct (see https://github.com/honoki/bbrf-server/pull/2)
        '''
        print('Downloading latest views from https://github.com/honoki/bbrf-server')
        r = self.requests_session.get('https://raw.githubusercontent.com/honoki/bbrf-server/main/couchdb/views.json')
        views = r.json()
        print('Comparing to current views...')
        admin_auth = 'Basic '+base64.b64encode((admin+':'+password).encode('utf-8')).decode('utf-8')
        r = self.requests_session.get(self.BBRF_API+'/_design/bbrf', headers={"Authorization": admin_auth})
        if r.status_code == 401:
            print('[Error] Wrong administrator credentials provided.')
            return
        rev = r.json()['_rev']
        if not self.docs_are_equal(r.json(), views):
            print('Pushing views to server...')
            views['_rev'] = rev
            r = self.requests_session.put(self.BBRF_API+'/_design/bbrf', json.dumps(views), headers={"Authorization": admin_auth, 'Content-Type': 'application/json'})
            if r.status_code == 201:
                print('Server upgrade complete, please allow a few minutes for all reindexing to complete. View the progress on '+self.BBRF_API.replace('/bbrf','')+'/_utils/#/activetasks')
            else:
                print('Unexpected error: '+str(r.status_code))
                print(r.text)
        else:
            print('Server already up to date.')
        print('Validating user access rights...')
        r = self.requests_session.get(self.BBRF_API+'/access-test') 
        if r.status_code == 401:
            print('No issues detected!')
        else:
            print('CRITICAL! Unauthorized access to the database is enabled. Fixing configuration...')
            r = self.requests_session.put(self.BBRF_API+'/_security', '{"admins":{"names":[]},"members":{"names":["bbrf"]}}', headers={"Authorization": admin_auth, 'Content-Type': 'application/json'})
            if r.status_code == 200:
                print('Configuration corrected, all\'s good!')
            else:
                print('Something went wrong when trying to correct the misconfiguration. Please run the following to fix manually:')
                print('curl -ik -X PUT "'+self.BBRF_API+'/_security" -u admin:password -d \'\'')
    
    def debug(self, msg):
        if self.do_debug:
            print('[DEBUG] '+msg)