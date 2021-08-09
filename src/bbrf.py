#!/usr/bin/python3

"""BBRF Client

Usage:
  bbrf ( new | use | disable | enable | rm ) <program> [ -t key:value ]...
  bbrf programs [ --show-disabled --show-empty-scope ]
  bbrf programs where <tag_name> is [ before | after ] <value> [ --show-disabled --show-empty-scope ]
  bbrf program ( active | update ( <program>... | - ) -t key:value... [--append-tags])
  bbrf domains [ --view <view> ( -p <program> | ( --all [--show-disabled] ) ) ]
  bbrf domains where <tag_name> is [ before | after ] <value> [ -p <program> | ( --all [--show-disabled] ) ]
  bbrf domain ( add | remove | update ) ( - | <domain>... ) [ -p <program> -s <source> --show-new ( -t key:value... [--append-tags] ) ]
  bbrf ips [ --filter-cdns ( -p <program> | ( --all [--show-disabled] ) ) ]
  bbrf ips where <tag_name> is [ before | after ] <value> [ -p <program> | ( --all [--show-disabled] ) ]
  bbrf ip ( add | remove | update ) ( - | <ip>... ) [ -p <program> -s <source> --show-new ( -t key:value... [--append-tags] ) ]
  bbrf scope ( in | out ) [ (--wildcard [--top] ) ] [ ( -p <program> ) | ( --all [--show-disabled] ) ]
  bbrf scope filter ( in | out ) [ (--wildcard [--top] ) ] [ ( -p <program> ) | ( --all [--show-disabled] ) ]
  bbrf ( inscope | outscope ) ( add | remove ) ( - | <element>... ) [ -p <program> ]
  bbrf urls [ -d <hostname> | ( -p <program> | ( --all [--show-disabled] ) ) ] [ --with-query | --root ]
  bbrf urls where <tag_name> is [ before | after ] <value> [ -p <program> | ( --all [--show-disabled] ) ]
  bbrf url add ( - | <url>... ) [ -d <hostname> -s <source> -p <program> --show-new ( -t key:value... [--append-tags] ) ]
  bbrf url remove ( - | <url>... )
  bbrf services [ -p <program> | ( --all [--show-disabled] ) ]
  bbrf services where <tag_name> is [ before | after ] <value> [ -p <program> | ( --all [--show-disabled] ) ]
  bbrf service add ( - | <service>... ) [ -s <source> -p <program> --show-new ( -t key:value... [ --append-tags ] ) ]
  bbrf service remove ( - | <service>... )
  bbrf blacklist ( add | remove ) ( - | <element>... ) [ -p <program> ]
  bbrf agents
  bbrf agent ( list | ( register | remove ) <agent>... | gateway [ <url> ] )
  bbrf run <agent> [ -p <program> ]
  bbrf show ( - | <document>... )
  bbrf listen
  bbrf alert ( - | <message>... ) [ -s <source> --show-new -t key:value... ] 
  bbrf tags [<name>] [ -p <program> | --all ] 
  bbrf server upgrade [-y]

Options:
  -h --help            Show this screen.
  -p <program>         Select a program to limit the command to. Not required when the command "use" has been run before.
  -t key:value         Specify one or more custom tags to add to your document. Format as key:value
  -s <source>          Provide an optional source string to store information about the source of the modified data.
  -v --version         Show the program version
  -d <hostname>        Explicitly specify the hostname of a URL in case of relative paths
  -n, --show-new       Print new unique values that were added to the database, and didn't already exist
  -A, --all            Specify to get information across all programs. Incompatible with the -p flag
  -a, --append-tags    If a tag with the same name already exists on the document, make an array and append the new value(s)
  -q, --with-query     When listing URLs, show all URLs including queries
  -r, --root           When listing URLs, only list the roots of the URLs
  -w, --show-disabled  Combine with the flag --all/-A to include documents of disabled programs too
"""

import os
import sys
import json
import re
from . import bbrf_api
from urllib.parse import urlparse
from docopt import docopt

CONFIG_FILE = '~/.bbrf/config.json'
# Thanks https://regexr.com/3au3g
REGEX_DOMAIN = re.compile('^(?:[a-z0-9_](?:[a-z0-9-_]{0,61}[a-z0-9])?\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
# regex to match IP addresses and CIDR ranges - thanks https://www.regextester.com/93987
REGEX_IP = re.compile('^([0-9]{1,3}\\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$')
VERSION = '1.1.15'

class BBRFClient:
    config = {}
    file_config = None
    arguments = None
    api = None
    
    def __init__(self, arguments, config=None):
        
        if not str(type(arguments)) == "<class 'docopt.Dict'>":
            self.arguments = docopt(__doc__, argv=arguments, version=VERSION)
        else:
            self.arguments = arguments
            
        if not config:
            self.load_config()
            self.file_config = True
        else:
            self.config = config
            self.file_config = False
        
        if 'username' not in self.config:
            exit('[ERROR] Required configuration was not found: username')
        elif 'password' not in self.config:
            exit('[ERROR] Required configuration was not found: password')
        elif 'couchdb' not in self.config:
            exit('[ERROR] Required configuration was not found: couchdb')
        
        else:
            self.api = bbrf_api.BBRFApi(
                self.config['couchdb'],
                self.config['username'],
                self.config['password'],
                slack_token=self.config['slack_token'] if 'slack_token' in self.config else None,
                slack_channel=self.config['slack_channel'] if 'slack_channel' in self.config else 'bbrf',
                discord_webhook = self.config['discord_webhook'] if 'discord_webhook' in self.config else None,
                slack_webhook = self.config['slack_webhook'] if 'slack_webhook' in self.config else None,
                ignore_ssl_errors = self.config['ignore_ssl_errors'] if 'ignore_ssl_errors' in self.config else None,
                debug = self.config['debug'] if 'debug' in self.config else False
            )

    def new_program(self):
        # First set the program as the active one
        self.use_program(False)
         # If the program name seems to be a domain name, issue a warning
        # that this is not the ideal formatting
        if REGEX_DOMAIN.match(self.get_program()):
            print('[WARNING] You are adding a program name that looks like a domain name, which is discouraged. You will now not be able to add the domain '+self.get_program()+' to your database')
        # and add it to the db
        self.api.create_new_program(self.get_program(), tags=self.arguments['-t'])

    def list_programs(self, show_disabled, show_empty_scope):
        return self.api.get_programs(show_disabled=show_disabled, show_empty_scope=show_empty_scope)
    
    # updating programs this way only supports tags for now
    def update_programs(self, programs):
        update_programs = {}
            
        for program in programs:
            
            if(self.arguments['-t'] and len(self.arguments['-t']) > 0):
                update_programs[program] = {}
                update_programs[program]['tags'] = self.api.process_tags(self.arguments['-t'])
            
        updated = self.api.update_documents('program', {program: update_programs[program] for program in update_programs.keys()}, append_tags=self.arguments['--append-tags'])
    
    def list_agents(self):
        return [r['key'] for r in self.api.get_agents()]
    
    def register_agents(self, agent_names):
        for agent in agent_names:
            try:
                self.api.create_new_agent(agent)
            except:
                # this agent probably exists already
                print('Error adding new agent ' + agent + '...')
    
    def remove_agents(self, agent_names):
        for agent in agent_names:
            try:
                self.api.remove_document('agent', {'key': agent})
            except:
                continue
    
    '''
    Specify a program to be used, and avoid having to type -p <name>
    for every command. The config is stored in CONFIG_FILE.
    '''
    def use_program(self, check_exists=True):
        pro = self.arguments['<program>']
        if type(pro) is list:
            pro = pro[0]
        if check_exists and pro not in self.list_programs(True, True):
            raise Exception('This program does not exist.')
        self.config['program'] = pro
    
    '''
    Check whether an IP belongs to a CIDR range
    '''
    def ip_in_cidr(self, ip, cidr):
        from ipaddress import ip_network, ip_address
        return ip_address(ip) in ip_network(cidr)

    '''
    Make abstraction of where the program comes from. It should be either
    specified via the "use" command, or otherwise provided as the -p argument.
    '''
    def get_program(self):
        if self.arguments['-p']:
            return self.arguments['-p']
        elif 'program' in self.config:
            return self.config['program']
        else:
            raise Exception('You need to select a program to execute this action.')
 
    def get_scope(self):   
        if not self.arguments['--all']:
            if self.arguments['in']:
                (_, scope, _) = self.api.get_program_scope(self.get_program())
            elif self.arguments['out']:
                (_, _, scope) = self.api.get_program_scope(self.get_program())
        else: # get scope across all programs, making use of _view/scope
            inscope, outscope = self.api.get_scopes(show_disabled = self.arguments['--show-disabled'])
            if self.arguments['in']:
                scope = inscope
            elif self.arguments['out']:
                scope = outscope

        # filter the scope if --wildcard and/or --top flags are set
        if(self.arguments['--wildcard']):
            r_scope = []
            for s in scope:
                if s.startswith('*.'):
                    r_scope.append(s[2:])
            # only return top-level scope,
            # i.e. 
            if(self.arguments['--top']):
                all_scope = r_scope[:]  # make a copy of the scope before editing it
                for s in all_scope:  # run through each of the wildcard domains
                    for t in r_scope: # and compare to our limited scope copy
                        if s != t and t.endswith(s):
                            r_scope.remove(t)
                        elif s != t and s.endswith(t):
                            if s in r_scope:
                                r_scope.remove(s)

            return r_scope
        else:
            return scope

    def filter_scope(self):
        '''
        Compare stdin to the defined scope of the program and return the values that are considered in or out of scope
        '''
        if not self.arguments['--all']:
            (_, inscope, outscope) = self.api.get_program_scope(self.get_program())
        else:
            inscope, outscope = self.api.get_scopes()
        
        if self.arguments['in']:
            # if filtering against the inscope, we also need to ensure it's NOT in the outscope to avoid confusion
            match = ( line for line in process_stdin() if self.matches_scope(line, inscope) )
            return [ line for line in match if not self.matches_scope(line, outscope) ]
        else:
            # otherwise, print everything that matches the outscope + everything that does not match the inscope
            return [ line for line in process_stdin() if self.matches_scope(line, outscope) or not self.matches_scope(line, inscope) ]

    '''
    The BBRF client is responsible for ensuring the added domain is not explicitly outscoped,
    and conforms to the expected format of a domain.
    
    Expected format:
        domains = [
         "a.example.com",
         "b.example.com",
         "c.example.com:1.2.3.4"
         "d.example.com:1.2.3.4,10.0.0.1"
        ]
        
    If a line includes a : delimiter, strip off the ips and add them to the database
    '''
    def add_domains(self, domains):
        (copy, inscope, outscope) = self.api.get_program_scope(self.get_program())
        add_domains = {}
        add_inscope = []
        
        # Keep a copy of the blacklist for reference
        blacklist = self.get_blacklist(copy=copy)
        
        for domain in domains:
            blacklisted_ip = False
            ips = []
            domain = domain.lower()
            
            if ':' in domain:
                domain, ips = domain.split(':',1)
                ips = ips.split(',')
                
                for ip in ips:
                    if ip in blacklist:
                        blacklisted_ip = True
                    if not REGEX_IP.match(ip):
                        ips.remove(ip)
                    
            
            # housekeeping
            if domain.endswith('.'):
                domain = domain[:-1]
            
            # not entirely sure this will ever occur, but hey (update: it does occur, as a result of crt.sh)
            # it makes sense to do this here, because it will still check whether it is in scope
            # before extending the existing scope.
            if domain.startswith('*.'):
                domain = domain[2:]
                # if it matches the existing scope definition,
                # add this wildcard to the scope too
                if REGEX_DOMAIN.match(domain) and not self.matches_scope(domain, outscope) and self.matches_scope(domain, inscope):
                    add_inscope.append('*.'+domain)
                    
            # Avoid adding blacklisted domains or
            # domains that resolve to blacklisted ips
            if blacklisted_ip or domain in blacklist:
                self.debug('blacklisted: '+domain)
                continue
            # It must match the format of a domain name
            if not REGEX_DOMAIN.match(domain):
                self.debug('REGEX_DOMAIN failed: '+domain)
                continue
            # It may not be explicitly outscoped
            if self.matches_scope(domain, outscope):
                self.debug('outscope: '+domain)
                continue
            # It must match the in scope, except if we're trying to @INFER the program later,
            # which means we cannot verify the scope here
            if not self.get_program() == '@INFER' and not self.matches_scope(domain, inscope):
                self.debug('Not inscope: '+domain)
                continue
                
            # leading underscores are not allowed in couchdb,
            # so we need to somehow escape them.
            if domain.startswith('_'):
                domain = '.'+domain
                
            # Add the ips if we already parsed other ips for this domain,
            # or otherwise create a new one
            if domain in add_domains and type(add_domains[domain]) is list:
                add_domains[domain].extend(ips)
            else:
                add_domains[domain] = ips
                
        # add all new scope at once to drastically reduce runtime of large input
        if len(add_inscope) > 0:
            self.add_inscope(add_inscope, passalong={'doc':copy, 'inscope':inscope, 'outscope':outscope})
        
        if len(add_domains) > 0:
            success, _ = self.api.add_documents('domain', add_domains, self.get_program(), source=self.arguments['-s'], tags=self.arguments['-t'])
        
            if self.arguments['--show-new'] and success:
                return ["[NEW] "+(x if not x.startswith('._') else x[1:]) for x in success if x]
    
    '''
    Use the bulk update function to mass remove domains.
    '''
    def remove_domains(self, domains):
        
        remove = {(domain if not domain.startswith('_') else '.'+domain ): {'_deleted': True} for domain in domains}
        removed = self.api.update_documents('domain', remove)
        
        if self.arguments['--show-new'] and removed:
            return ["[DELETED] "+(x if not x.startswith('._') else x[1:]) for x in removed if x]
        
    '''
    Remove all documents related to a program.
    '''
    def remove_program(self, program):
        all_docs = self.api.get_all_program_documents(program)
        remove_domains = {docid: {'_deleted': True} for (docid, doctype) in all_docs if doctype == 'domain' }
        remove_ips = {docid: {'_deleted': True} for (docid, doctype) in all_docs if doctype == 'ip' }
        remove_urls = {docid: {'_deleted': True} for (docid, doctype) in all_docs if doctype == 'url' }
        remove_services = {docid: {'_deleted': True} for (docid, doctype) in all_docs if doctype == 'service' }
        
        self.api.update_documents('domain', remove_domains)
        self.api.update_documents('ip', remove_ips)
        self.api.update_documents('url', remove_urls)
        self.api.update_documents('service', remove_services)
        self.api.update_documents('program', {program: {'_deleted': True}})

    '''
    Update properties of a domain
    '''
    def update_domains(self, domains):
        update_domains = {}
            
        for domain in domains:
            
            ips = []
            domain = domain.lower()
            
            # split ips if provided
            if ':' in domain:
                domain, ips = domain.split(':')
                ips = ips.split(',')
                
                for ip in ips:
                    if not REGEX_IP.match(ip):
                        ips.remove(ip)
                
            # housekeeping
            if domain.endswith('.'):
                domain = domain[:-1]
            # leading underscores are not allowed in couchdb,
            # so we need to somehow escape them.
            if domain.startswith('_'):
                domain = '.'+domain
                
            # Add the ips if we already parsed other ips for this domain,
            # or otherwise create a new one
            if domain in update_domains and type(update_domains[domain]['ips']) is list:
                update_domains[domain]['ips'].extend(ips)
            else:
                update_domains[domain] = {"ips": ips}
            
            if(self.arguments['-t'] and len(self.arguments['-t']) > 0):
                update_domains[domain]['tags'] = self.api.process_tags(self.arguments['-t'])
                
            if self.arguments['-s']:
                update_domains[domain]['source'] = self.arguments['-s']
        
        updated = self.api.update_documents('domain', {domain: update_domains[domain] for domain in update_domains.keys()}, append_tags=self.arguments['--append-tags'])
        
        if self.arguments['--show-new'] and updated:
            return [ "[UPDATED] "+(x if not x.startswith('._') else x[1:]) for x in updated if x]
    
    def add_ips(self, ips):
        add_ips = {}
        
        # Keep a copy of the blacklist for reference
        blacklist = self.get_blacklist()
        
        for ip in ips:
            
            blacklisted_domain = False
            domains = []
            
            if ':' in ip:
                ip, domains = ip.split(':')
                domains = domains.split(',')
                
                for domain in domains:
                    if not REGEX_DOMAIN.match(domain):
                        domains.remove(domain)
#                    if domain in blacklist:
#                        blacklisted_domain = True
            
            if blacklisted_domain:
                continue
            if ip in blacklist:
                continue
            if not REGEX_IP.match(ip):
                continue
           
            if ip in add_ips and type(add_ips[ip]) is list:
                add_ips[ip].extend(domains)
            else: 
                add_ips[ip] = domains

        success, _ = self.api.add_documents('ip', add_ips, self.get_program(), source=self.arguments['-s'], tags=self.arguments['-t'])
        
        if self.arguments['--show-new'] and success:
            return ["[NEW] "+x for x in success if x]
        
    def remove_ips(self, ips):

        remove = {ip: {'_deleted': True} for ip in ips}
        removed = self.api.update_documents('ip', remove)
        
        if self.arguments['--show-new'] and removed:
            return ["[DELETED] "+x for x in removed if x] 
            
    '''
    Update properties of an IP
    '''
    def update_ips(self, ips):
        
        update_ips = {}
            
        for ip in ips:
            
            domains = []
            if ':' in ip:
                ip, domains = ip.split(':')
                domains = domains.split(',')
                
            # housekeeping
            updated_domains = []
            for domain in domains:
                if domain.endswith('.'):
                    domain = domain[:-1]
                if REGEX_DOMAIN.match(domain):
                    updated_domains.append(domain)
            
            # Add the domains if we already parsed other domains for this ip,
            # or otherwise create a new one
            if ip in update_ips and type(update_ips[ip]['domains']) is list:
                update_ips[ip]['domains'].extend(updated_domains)
            else:
                update_ips[ip] = {"domains": updated_domains}
            
            if(self.arguments['-t'] and len(self.arguments['-t']) > 0):
                update_ips[ip]['tags'] = self.api.process_tags(self.arguments['-t'])
                
            if self.arguments['-s']:
                update_ips[ip]['source'] = self.arguments['-s']
            
        updated = self.api.update_documents('ip', {ip: update_ips[ip] for ip in update_ips.keys()}, append_tags=self.arguments['--append-tags'])
        
        if self.arguments['--show-new'] and updated:
            return [ "[UPDATED] "+x for x in updated if x]
    
    '''
    The BBRF client is responsible for ensuring the added urls are added to the appropriate hostname (domain or IP),
    unless a hostname is explicitly provided.
    
    If spaces are found, the input will be split in three parts: path, status code and response size, and the tool will 
    store those as part of the url.
    
    Expected format:
        urls = [
         "http://a.example.com:8080/test",
         "//b.example.com/example",
         "/robots.txt",
         "/page 200 9209",
         "http://hostname.com/page 401 170"
        ]
            
    The database stores urls as individual documents with:
     - identifier (url)
     - status
     - content_length
     - hostname (referencing a domain)
     - program
     
    '''
    def add_urls(self, urls):
        
        (_, inscope, outscope) = self.api.get_program_scope(self.get_program())
        add_urls = {}
        
        for url in urls:
            parts = url.split(' ')
            url = parts[0]
            
            # To support urls without a schema that aren't relative URLS
            # e.g. '    www.example.com', add a leading protocol 
            if not url.startswith('http://') and not url.startswith('https://') and not url.startswith('/'):
                url = 'http://'+url
                
            # parse properties of the URL
            u = urlparse(url)
            scheme = u.scheme
            port = u.port
            query = u.query if u.query else None
            
            # Usually we parse the hostname from the URL,
            # but we don't need to if a hostname is explicitly set
            if not self.arguments['-d']:
                hostname = u.hostname
            else:
                hostname = self.arguments['-d']
                                          
            # It's still possible hostname is empty, e.g. for
            # bbrf url add '/relative' without a -d hostname set;
            # We can't process relative URLS without understanding,
            # so need to skip those for now. Better ideas wecome!
            if not hostname:
                self.debug("Hostname could not be parsed, skipping "+url)
                continue
            
            # If the provided hostname in -d does not match the parsed hostname,
            # we won't add it to avoid polluting the dataset
            if u.hostname and not u.hostname == hostname:
                self.debug("Provided hostname "+hostname+" did not match parsed hostname "+u.hostname+", skipping...")
                continue
                
            # If the provided URL is relative, we need to rewrite the URL
            # with the provided hostname, and we will ALWAYS assume http port 80
            if not u.netloc:
                url = 'http://' + hostname + url
                port = 80
                scheme = 'http'
            if url.startswith('//'):
                url = 'http:' + url
                port = 80
                scheme = 'https'
            if '?' in url:
                url = url.split('?')[0]
                
            # It must match the format of a domain name or an IP address
            if not REGEX_DOMAIN.match(hostname) and not REGEX_IP.match(hostname):
                self.debug("Illegal hostname: "+hostname)
                continue
            # It may not be explicitly outscoped
            if not self.get_program() == '@INFER' and self.matches_scope(hostname, outscope):
                self.debug("skipping outscoped hostname: "+hostname)
                continue
            # It must match the in scope
            if not self.get_program() == '@INFER' and not self.matches_scope(hostname, inscope):
                self.debug("skipping not inscope hostname: "+hostname)
                continue
            
            if not port:
                if scheme == 'http':
                    port = 80
                if scheme == 'https':
                    port = 443
            
            # remove explicit ports 80 and 443 to avoid duplicate values
            # when they are also added without the ports
            if port == 80 and ':80/' in url:
                url = url.replace(':80/', '/', 1)
            elif port == 443 and ':443/' in url:
                url = url.replace(':443/', '/', 1)
            
            if url in add_urls and query and query not in add_urls[url]['query']:
                add_urls[url]['query'].append(query)
            else:
                if len(parts) == 1: # only a url
                    if not url in add_urls:
                        add_urls[url] = {
                            "hostname": hostname,
                            "port": int(port),
                            "query": [query] if query else [],
                            "scheme": scheme,
                            "path": u.path
                        }

                elif len(parts) == 3: # url, status code and content length
                    add_urls[url] = {
                        "hostname": hostname,
                        "port": int(port),
                        "status": int(parts[1]),
                        "content_length": int(parts[2]),
                        "query": [query] if query else [],
                        "scheme": scheme,
                        "path": u.path
                    }
        
        success, failed = self.api.add_documents('url', add_urls, self.get_program(), source=self.arguments['-s'], tags=self.arguments['-t'])
        
        # assuming the failed updates were the result of duplicates, try bulk updating the url that failed
        # but first add the tags to the document in case they need to be updated too
        if(self.arguments['-t'] and len(self.arguments['-t']) > 0):
            for url in failed:
                add_urls[url]['tags'] = self.api.process_tags(self.arguments['-t'])
        updated = self.api.update_documents('url', {url: add_urls[url] for url in failed}, append_tags=self.arguments['--append-tags'])
        
        
        results = []
        if self.arguments['--show-new'] and updated:
            results = [ "[UPDATED] "+x for x in updated if x]
        if self.arguments['--show-new'] and success:
            results = results + ["[NEW] "+x for x in success if x]
        if len(results) > 0:
            return results
        
    '''
    Remove URLs
    '''
    def remove_urls(self, urls):
        
        # parse first comma-seperated value as the url to remove
        # to support `bbrf urls -d example.com | bbrf url remove -`
        
        remove = {url.split(" ")[0]: {'_deleted': True} for url in urls}
        _ = self.api.update_documents('url', remove)
        
    '''
    Remove Services
    '''
    def remove_services(self, services):
        remove = {service: {'_deleted': True} for service in services}
        _ = self.api.update_documents('service', remove)
        
        
    '''
    Store services (i.e. open ports) of IP addresses
    
    The identifier will always 
    
    Expected format:
    
        services = [
         "127.0.0.1:80",
         "127.0.0.1:80:http",
         "127.0.0.1:443,
         "127.0.0.1:8443:https"
        ]
    '''
    def add_services(self, services):
        
        # TODO: should this be matched against scope?
        # BBRF doesn't currently support IPs or CIDR as scope, so
        # this would require some additional features a that level.
        # 
        # (inscope, outscope) = self.api.get_program_scope(self.get_program())
        add_services = {}
        for service in services:
            
            ip = None
            port = None
            sname = None
            
            if ':' in service:
                ip, port = service.split(':', 1)
                
                if ':' in port:
                    port, sname = port.split(':', 1)

            if not ip or not port:
                continue
            
            if not REGEX_IP.match(ip):
                continue
            if not port.isnumeric():
                continue
            if int(port) < 0 or int(port) > 65535:
                continue
            
            sid = ip+':'+port
           
            add_services[sid] = {'ip': ip, 'port': port}
            if self.arguments['-s']:
                add_services[sid]['source'] = self.arguments['-s']
                
            if sname:
                add_services[sid]['service'] = sname

        success, failed = self.api.add_documents('service', add_services, self.get_program(), source=self.arguments['-s'], tags=self.arguments['-t'])
        
        # assuming the failed updates were the result of duplicates, try bulk updating the services that failed
        # but first add the tags to the document in case they need to be updated too
        if(self.arguments['-t'] and len(self.arguments['-t']) > 0):
            for sid in failed:
                add_services[sid]['tags'] = self.api.process_tags(self.arguments['-t'])
                
        updated = self.api.update_documents('service', {sid: add_services[sid] for sid in failed}, append_tags=self.arguments['--append-tags'])
        
        results = []
        if self.arguments['--show-new'] and updated:
            results = [ "[UPDATED] "+x for x in updated if x]
        if self.arguments['--show-new'] and success:
            results = results + ["[NEW] "+x for x in success if x]
        if len(results) > 0:
            return results
        
    def add_alerts(self, alerts):
        import time
        
        add_alerts = {}
        for alert in alerts:
            add_alerts[alert] = {
                'timestamp': time.time(),
                'message': alert # for backwards compatibility
            }
        
        success, failed = self.api.add_documents('alert', add_alerts, self.get_program(), source=self.arguments['-s'], tags=self.arguments['-t'])
        
        if self.arguments['--show-new'] and success:
            return ["[NEW] "+x for x in success if x]
        
    
    def disable_program(self, program):
        self.api.update_document("program", program, {"disabled":True})
        
    def enable_program(self, program):
        self.api.update_document("program", program, {"disabled":False})
        
    def add_inscope(self, elements, passalong={}):
        doc = passalong['doc'] if 'doc' in passalong else None  
        inscope = passalong['inscope'] if 'inscope' in passalong else None
        outscope = passalong['outscope'] if 'outscope' in passalong else None
        
        if not doc or not inscope or not outscope:
            (doc, inscope, outscope) = self.api.get_program_scope(self.get_program())
        changed = False
        
        for e in elements:
            e = e.lower()
            if e not in inscope:
                if REGEX_DOMAIN.match(e) or e.startswith('*.') and REGEX_DOMAIN.match(e[2:]):
                    changed = True
                    inscope.append(e)
                # try to parse as a URL and consider the hostname as inscope
                else:
                    u = urlparse(e).hostname.lower()
                    if u not in inscope and REGEX_DOMAIN.match(u):
                        changed = True
                        inscope.append(u)
        
        if changed:
            self.api.update_program_scope(self.get_program(), inscope, outscope, program=doc)
    
    def remove_inscope(self, elements):
        (doc, inscope, outscope) = self.api.get_program_scope(self.get_program())
        
        changed = False
        
        for e in elements:
            e = e.lower()
            if e and e in inscope:
                changed = True
                inscope.remove(e)
                
        if changed:
            self.api.update_program_scope(self.get_program(), inscope, outscope, program=doc)
        
    def add_outscope(self, elements):
        (doc, inscope, outscope) = self.api.get_program_scope(self.get_program())
        
        changed = False
        
        for e in elements:
            e = e.lower()
            if e not in outscope:
                if REGEX_DOMAIN.match(e) or e.startswith('*.') and REGEX_DOMAIN.match(e[2:]):
                    changed = True
                    outscope.append(e)
                # try to parse as a URL and consider the hostname as outscope
                else:
                    u = urlparse(e).hostname.lower()
                    if u not in inscope and REGEX_DOMAIN.match(u):
                        changed = True
                        outscope.append(u)
        
        if changed:
            self.api.update_program_scope(self.get_program(), inscope, outscope, program=doc)
    
    def remove_outscope(self, elements):
        (doc, inscope, outscope) = self.api.get_program_scope(self.get_program())
        
        changed = False
        
        for e in elements:
            e = e.lower()
            if e and e in outscope:
                changed = True
                outscope.remove(e)
                
        if changed:
            self.api.update_program_scope(self.get_program(), inscope, outscope, program=doc)
    
    def list_ips(self, list_all = False):
        if list_all:
            return self.api.get_ips_by_program_name(show_disabled=self.arguments['--show-disabled'])
        return self.api.get_ips_by_program_name(self.get_program())
    
    def list_ips_no_cdn(self, list_all = False):
        if list_all:
            return self.api.get_ips_by_program_name(filter_cdn=True, show_disabled=self.arguments['--show-disabled'])
        return self.api.get_ips_by_program_name(program_name=self.get_program(), filter_cdn=True)
    
    def list_domains(self, list_all = False):
        if list_all:
            return self.api.get_domains_by_program_name(show_disabled=self.arguments['--show-disabled'])
        return [x if not x.startswith('._') else x[1:] for x in self.api.get_domains_by_program_name(self.get_program())]
    
    def list_urls(self, by, key = False):
        if by == "hostname":
            return self.api.get_urls_by_hostname(key, with_query=self.arguments['--with-query'], root_only=self.arguments['--root'])
        elif by == "program":
            return self.api.get_urls_by_program(key, with_query=self.arguments['--with-query'], root_only=self.arguments['--root'])
        elif by == "all":
            return self.api.get_urls_by_program(with_query=self.arguments['--with-query'], root_only=self.arguments['--root'], show_disabled=self.arguments['--show-disabled']) # An empty key will return all results
        else:
            return self.api.get_urls_by_program(self.get_program(), with_query=self.arguments['--with-query'], root_only=self.arguments['--root'])
        
    def list_services(self, list_all = False):
        if list_all:
            return self.api.get_services_by_program_name(show_disabled=self.arguments['--show-disabled'])
        return self.api.get_services_by_program_name(self.get_program())
    
    def list_documents_view(self, doctype, view, list_all = False):
        if list_all:
            return self.api.get_documents_view(None, doctype, view, show_disabled=self.arguments['--show-disabled'])
        return self.api.get_documents_view(self.get_program(), doctype, view)
    
    def get_blacklist(self, copy=None):
        return self.api.get_program_blacklist(self.get_program(), doc=copy)
    
    def add_blacklist(self, elements):
        blacklist = self.get_blacklist()
        
        for e in elements:
            if e not in blacklist:
                blacklist.append(e)
        
        self.api.update_program_blacklist(self.get_program(), blacklist)
    
    def remove_blacklist(self, elements):
        blacklist = self.get_blacklist()
        
        for e in elements:
            if e in blacklist:
                blacklist.remove(e)
                
        self.api.update_program_blacklist(self.get_program(), blacklist)
        
    def load_config(self):
        with open(os.path.expanduser(CONFIG_FILE)) as json_file:
            self.config = json.load(json_file)

    def save_config(self):
        if self.file_config:
            with open(os.path.expanduser(CONFIG_FILE), 'w') as outfile:
                json.dump(self.config, outfile)
            
    def listen_for_changes(self):
        self.api.listen_for_changes()
        
    def search_tags(self, doctype):
        # Always use the active program unless --all is specified
        program_name = self.get_program()
        if(self.arguments['--all']):
            program_name = False

        if(self.arguments['before']):
            return self.api.search_tags_between(self.arguments['<tag_name>'], self.arguments['<value>'], 'before', doctype, program_name, show_disabled=self.arguments['--show-disabled'], show_empty_scope=self.arguments['--show-empty-scope'])
        if(self.arguments['after']):
            return self.api.search_tags_between(self.arguments['<tag_name>'], self.arguments['<value>'], 'after', doctype, program_name, show_disabled=self.arguments['--show-disabled'], show_empty_scope=self.arguments['--show-empty-scope'])
        else:
            return [x if not x.startswith('._') else x[1:] for x in self.api.search_tags(self.arguments['<tag_name>'], self.arguments['<value>'], doctype, program_name, show_disabled=self.arguments['--show-disabled'], show_empty_scope=self.arguments['--show-empty-scope'])]
    
    def list_tags(self, tagname):
        # Always use the active program unless --all is specified
        program_name = self.get_program()
        if(self.arguments['--all']):
            program_name = False
        return self.api.get_tags(tagname, program_name)
        
    '''
    Check whether a domain matches a scope
    '''
    @staticmethod
    def matches_scope(domain, scope):
        for s in scope:
            # literal match
            if s == domain:
                return True
            # x.example.com matches *.example.com
            if s.startswith('*.') and domain.endswith('.'+s[2:]):
                return True
        return False    
    
    def debug(self, msg):
        if 'debug' in self.config and self.config['debug']:
            print('[DEBUG] '+msg)
        
    def run(self):
        
        import pprint
        pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(self.arguments)
        
        if not self.config:
            try:
                self.load_config()
            except Exception:
                print('[WARNING] Could not read config file - make sure it exists and is readable')

        if self.arguments['new']:
            self.new_program()

        if self.arguments['use']:
            self.use_program()
            
        if self.arguments['disable']:
            self.disable_program(self.arguments['<program>'][0])
            
        if self.arguments['enable']:
            self.enable_program(self.arguments['<program>'][0])
            
        if self.arguments['rm']:
            self.remove_program(self.arguments['<program>'][0])

        if self.arguments['programs']:
            if self.arguments['where']:
                return self.search_tags("program")
            return self.list_programs(self.arguments['--show-disabled'], self.arguments['--show-empty-scope'])
            
        if self.arguments['program']:
            if self.arguments['active']:
                return self.get_program()
            if self.arguments['update']:
                return self.update_programs(self.arguments['<program>'])
            else:
                return self.get_program()

        if self.arguments['domains']:
            if self.arguments['<view>']:
                return self.list_documents_view("domain", self.arguments['<view>'], self.arguments['--all'])
            elif self.arguments['where']:
                return self.search_tags("domain")
            else:
                return self.list_domains(self.arguments['--all'])

        if self.arguments['domain']:
            if self.arguments['add']:
                if self.arguments['<domain>']:
                    return self.add_domains(self.arguments['<domain>'])
                elif self.arguments['-']:
                    return self.add_domains(process_stdin())
            if self.arguments['remove']:
                if self.arguments['<domain>']:
                    return self.remove_domains(self.arguments['<domain>'])
                elif self.arguments['-']:
                    return self.remove_domains(process_stdin())
            if self.arguments['update']:
                if self.arguments['<domain>']:
                    return self.update_domains(self.arguments['<domain>'])
                elif self.arguments['-']:
                    return self.update_domains(process_stdin())

        if self.arguments['ips']:
            if self.arguments['--filter-cdns']:
                return self.list_ips_no_cdn(self.arguments['--all'])
            elif self.arguments['where']:
                return self.search_tags("ip")
            return self.list_ips(self.arguments['--all'])

        if self.arguments['ip']:
            if self.arguments['add']:
                if self.arguments['<ip>']:
                    return self.add_ips(self.arguments['<ip>'])
                elif self.arguments['-']:
                    return self.add_ips(process_stdin())
            if self.arguments['remove']:
                if self.arguments['<ip>']:
                    self.remove_ips(self.arguments['<ip>'])
                elif self.arguments['-']:
                    self.remove_ips(process_stdin())
            if self.arguments['update']:
                if self.arguments['<ip>']:
                    return self.update_ips(self.arguments['<ip>'])
                elif self.arguments['-']:
                    return self.update_ips(process_stdin())

        if self.arguments['inscope']:
            if self.arguments['add']:
                if self.arguments['<element>']:
                    self.add_inscope(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.add_inscope(process_stdin())
            if self.arguments['remove']:
                if self.arguments['<element>']:
                    self.remove_inscope(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.remove_inscope(process_stdin())
                    
        if self.arguments['outscope']:
            if self.arguments['add']:
                if self.arguments['<element>']:
                    self.add_outscope(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.add_outscope(process_stdin())
            if self.arguments['remove']:
                if self.arguments['<element>']:
                    self.remove_outscope(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.remove_outscope(process_stdin())
                    
        if self.arguments['url']:
            if self.arguments['add']:
                if self.arguments['<url>']:
                    return self.add_urls(self.arguments['<url>'])
                if self.arguments['-']:
                    return self.add_urls([u.rstrip() for u in process_stdin()])
            if self.arguments['remove']:
                if self.arguments['<url>']:
                    return self.remove_urls(self.arguments['<url>'])
                if self.arguments['-']:
                    return self.remove_urls([u.rstrip() for u in process_stdin()])
                    
        if self.arguments['urls']:
            if self.arguments['-d']:
                return self.list_urls("hostname",self.arguments['-d'])
            elif self.arguments['where']:
                return self.search_tags("url")
            elif self.arguments['<program>']:
                return self.list_urls("program",self.arguments['<program>'])
            elif self.arguments['--all']:
                return self.list_urls("all")
            else:
                return self.list_urls("self")
            
        if self.arguments['service']:
            if self.arguments['add']:
                if self.arguments['<service>']:
                    return self.add_services(self.arguments['<service>'])
                if self.arguments['-']:
                    return self.add_services([u.rstrip() for u in process_stdin()])
            if self.arguments['remove']:
                if self.arguments['<service>']:
                    return self.remove_services(self.arguments['<service>'])
                if self.arguments['-']:
                    return self.remove_services([s.rstrip() for s in process_stdin()])
                
            
        if self.arguments['services']:
            if self.arguments['where']:
                return self.search_tags("service")
            else:
                return self.list_services(self.arguments['--all'])
            
        if self.arguments['blacklist']:
            if self.arguments['add']:
                if self.arguments['<element>']:
                    self.add_blacklist(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.add_blacklist(process_stdin())
            if self.arguments['remove']:
                if self.arguments['<element>']:
                    self.remove_blacklist(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.remove_blacklist(process_stdin())
        
        if self.arguments['agents']:
            return self.list_agents()
            
        if self.arguments['agent']:
            if self.arguments['list']:
                return self.list_agents()
            if self.arguments['remove']:
                self.remove_agents(self.arguments['<agent>'])
            if self.arguments['register']:
                return self.register_agents(self.arguments['<agent>'])
            if self.arguments['gateway']:
                if self.arguments['<url>']:
                    return self.api.set_agent_gateway(self.arguments['<url>'][0])
                else:
                    return json.loads(self.api.get_document('agents_api_gateway')).get('url')
        
        if self.arguments['run']:
            return self.api.run_agent(self.arguments['<agent>'][0], self.get_program())
        
        if self.arguments['show']:
            if not self.arguments['-']:
                # fall back to get_document if a single document is requested,
                # for backwards compatibility, so we continue to return a single object
                # rather than an array.       
                if(len(self.arguments['<document>']) == 1):
                    return self.api.get_document(self.arguments['<document>'][0])
                
                return self.api.get_documents(self.arguments['<document>'])
            else:
                # if list of documents comes from stdin, we presume the
                # user does not know it might only contain one identifier, and should
                # always handle the output as an array
                return self.api.get_documents(process_stdin())
            

        if self.arguments['listen']:
            self.listen_for_changes()
            
        if self.arguments['alert']:
            if self.arguments['<message>']:
                return self.add_alerts(self.arguments['<message>'])
            elif self.arguments['-']:
                return self.add_alerts(process_stdin())
                    
        if self.arguments['scope']:
            if self.arguments['filter']:
                return self.filter_scope()
            else:
                return self.get_scope()
            
        if self.arguments['tags']:
            return self.list_tags(self.arguments['<name>'])
        
        if self.arguments['server']:
            import getpass
            admin = input('Admin username: ')
            password = getpass.getpass('Password: ')
            self.api.server_upgrade(admin, password)

        try:
            self.save_config()
        except Exception:
            print('[WARNING] Could not write to config file - make sure it exists and is writable')
            
def process_stdin():
    return filter(lambda x: not re.match(r'^\s*$', x),  sys.stdin.read().split('\n'))
            
def main():
    try:
        arguments = docopt(__doc__, version=VERSION)
        result = BBRFClient(arguments).run()
        if result:
            if type(result) is list:
                print("\n".join(result))
            else:
                print(result)
    except Exception as e:
        print('[ERROR] '+str(e))
            
if __name__ == '__main__':
    main()