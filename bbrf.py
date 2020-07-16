#!/usr/bin/python3

"""BBRF Client

Usage:
  bbrf (new|use) <program> [--disabled --passive-only]
  bbrf program (list|active|scope [--wildcard [--top]] [-p <program>])
  bbrf domains [--view <view>] [-p <program> --all]
  bbrf domain (add|remove|update) ( - | <domain>...) [-p <program>] [-s <source>]
  bbrf ips [--view <view>] [-p <program> | --all]
  bbrf ip (add|remove|update) ( - | <ip>...) [-p <program>] [-s <source>]
  bbrf (inscope|outscope) (add|remove) ([-] | <element>...) [-p <program>]
  bbrf blacklist (add|remove) ( - | <element>...) [-p <program>]
  bbrf task (list|(add|remove) <task>)
  bbrf run <task> [-p <program>]
  bbrf show <document>
  bbrf listen
  bbrf alert ( - | <message>) [-s <source>]
  bbrf --version

Options:
  -h --help     Show this screen.
  -p <program>  Select a program to limit the command to. Not required when the command "use" has been run before.
  -s <source>   Provide an optional source string to store information about the source of the modified data.
"""
from docopt import docopt
import os
import sys
import json
from bbrf_api import BBRFApi
import re
from multiprocessing import Pool

CONFIG_FILE = '~/.bbrf/config.json'

class BBRFClient:
    config = {}
    arguments = None
    api = None
    
    def __init__(self, arguments, config=None):
        
        if not str(type(arguments)) == "<class 'docopt.Dict'>":
            self.arguments = docopt(__doc__, argv=arguments, version='BBRF client 0.1b')
        else:
            self.arguments = arguments
            
        if not config:
            self.load_config()
        else:
            self.config = config
        
        if 'username' not in self.config:
            exit('[ERROR] Required configuration was not found: username')
        elif 'password' not in self.config:
            exit('[ERROR] Required configuration was not found: password')
        elif 'couchdb' not in self.config:
            exit('[ERROR] Required configuration was not found: couchdb')
        elif 'slack_token' not in self.config:
            exit('[ERROR] Required configuration was not found: slack_token')
        else:
            self.api = BBRFApi(self.config['couchdb'], self.config['username'], self.config['password'], self.config['slack_token'])

    def new_program(self):
        # First set the program as the active one
        self.use_program(False)
        # and add it to the db
        self.api.create_new_program(self.get_program())

    def list_programs(self):
        return self.api.get_programs()
    
    def list_tasks(self):
        return [r['key'] for r in self.api.get_tasks()]
    
    '''
    Specify a program to be used, and avoid having to type -p <name>
    for every command. The config is stored in CONFIG_FILE.
    '''
    def use_program(self, check_exists=True):
        pro = self.arguments['<program>']
        if check_exists and pro not in self.list_programs():
            raise Exception('This program does not exist.')
        self.config['program'] = self.arguments['<program>']
    
    '''
    Check whether a domain matches a scope
    '''
    def matches_scope(self, domain, scope):
        for s in scope:
            # literal match
            if s == domain:
                return True
            # x.example.com matches *.example.com
            if s.startswith('*.') and domain.endswith('.'+s[2:]):
                return True
        return False

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
 
    def get_program_scope(self):
        
        (inscope, _) = self.api.get_program_scope(self.get_program())
        if(self.arguments['--wildcard']):
            scope = []
            for s in inscope:
                if s.startswith('*.'):
                    scope.append(s[2:])
            # only return top-level scope,
            # i.e. 
            if(self.arguments['--top']):
                all_scope = scope[:]  # make a copy of the scope before editing it
                for s in all_scope:  # run through each of the wildcard domains
                    for t in scope: # and compare to our limited scope copy
                        if s != t and t.endswith(s):
                            scope.remove(t)
                        elif s != t and s.endswith(t):
                            if s in scope:
                                scope.remove(s)
                
            return scope
        else:
            return inscope
            
    '''
    List all domains in the current program.
    '''
    def list_domains(self, all_programs = False):
        if all_programs:
            return self.aip.get_domains_across_programs()
        return self.api.get_domains_by_program_name(self.get_program())
    
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
        # Thanks https://regexr.com/3au3g
        regex = re.compile('^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
        
        (inscope, outscope) = self.api.get_program_scope(self.get_program())
        add_domains = {}
        
        # Keep a copy of the blacklist for reference
        blacklist = self.get_blacklist()
        
        for domain in domains:
            blacklisted_ip = False
            ips = []
            
            if ':' in domain:
                domain, ips = domain.split(':')
                ips = ips.split(',')
                
                for ip in ips:
                    if ip in blacklist:
                        blacklisted_ip = True
            
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
                if regex.match(domain) and not self.matches_scope(domain, outscope) and self.matches_scope(domain, inscope):
                    self.add_inscope(['*.'+domain])
            
            # Avoid adding blacklisted domains or
            # domains that resolve to blacklisted ips
            if blacklisted_ip or domain in blacklist:
                continue
            # It must match the format of a domain name
            if not regex.match(domain):
                continue
            # It may not be explicitly outscoped
            if self.matches_scope(domain, outscope):
                continue
            # It must match the in scope
            if not self.matches_scope(domain, inscope):
                continue
            add_domains[domain] = ips
            
        self.api.add_documents('domain', add_domains, self.get_program(), source=self.arguments['-s'])
    
    '''
    This is now balanced over 100 concurrent threads in order to drastically
    improve the throughput of these requests.
    '''
    def remove_domains(self, domains):
        with Pool(40) as p:
            p.starmap(self.api.remove_document, [("domain", x) for x in domains])

    '''
    Update properties of a domain
    '''
    def update_domains(self, domains):
        update_domains = {}
            
        for domain in domains:
            
            ips = []
            # split ips if provided
            if ':' in domain:
                domain, ips = domain.split(':')
                ips = ips.split(',')
                
            # housekeeping
            if domain.endswith('.'):
                domain = domain[:-1]
                
            update_domains[domain] = {"ips": ips}
        
        with Pool(40) as p:
            p.starmap(self.api.update_document, [("domain", x, update_domains[x]) for x in update_domains.keys()])
    
    def add_ips(self, ips):
        # regex to match IP addresses and CIDR ranges - thanks https://www.regextester.com/93987
        regex = re.compile('^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$')
        
        add_ips = {}
        
        # Keep a copy of the blacklist for reference
        blacklist = self.get_blacklist()
        
        for ip in ips:
            
            blacklisted_domain = False
            domains = []
            
            if ':' in ip:
                ip, domains = ip.split(':')
                domains = domains.split(',')
                
#                for domain in domains:
#                    if domain in blacklist:
#                        blacklisted_domain = True
            
            if blacklisted_domain:
                continue
            if ip in blacklist:
                continue
            if not regex.match(ip):
                continue
           
            add_ips[ip] = domains

        self.api.add_documents('ip', add_ips, self.get_program())
        
    def remove_ips(self, ips):
        with Pool(100) as p:
            p.starmap(self.api.remove_document, [("ip", x) for x in ips])
            
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
            for domain in domains:
                if domain.endswith('.'):
                    domain = domain[:-1]
                
            update_ips[ip] = {"domains": domains}
            
        with Pool(40) as p:
            p.starmap(self.api.update_document, [("ip", x, update_ips[x]) for x in update_ips.keys()])
            
    def add_inscope(self, elements):
        (inscope, outscope) = self.api.get_program_scope(self.get_program())
        
        for e in elements:
            if e not in inscope:
                inscope.append(e)
        
        self.api.update_program_scope(self.get_program(), inscope, outscope)
    
    def remove_inscope(self, elements):
        (inscope, outscope) = self.api.get_program_scope(self.get_program())
        
        for e in elements:
            if e in inscope:
                inscope.remove(e)
                
        self.api.update_program_scope(self.get_program(), inscope, outscope)
        
    def add_outscope(self, elements):
        (inscope, outscope) = self.api.get_program_scope(self.get_program())
        
        for e in elements:
            if e not in outscope:
                outscope.append(e)
        
        self.api.update_program_scope(self.get_program(), inscope, outscope)
    
    def remove_outscope(self, elements):
        (inscope, outscope) = self.api.get_program_scope(self.get_program())
        
        for e in elements:
            if e in outscope:
                outscope.remove(e)
                
        self.api.update_program_scope(self.get_program(), inscope, outscope)
    
    def list_ips(self, list_all = False):
        if list_all:
            return self.api.get_ips_by_program_name()
        return self.api.get_ips_by_program_name(self.get_program())
    
    def list_domains(self, list_all = False):
        if list_all:
            return self.api.get_domains_by_program_name()
        return self.api.get_domains_by_program_name(self.get_program())
    
    def list_documents_view(self, doctype, view, list_all = False):
        if list_all:
            return self.api.get_documents_view(None, doctype, view)
        return self.api.get_documents_view(self.get_program(), doctype, view)
    
    def get_blacklist(self):
        return self.api.get_program_blacklist(self.get_program())
    
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
                blacklist.delete(e)
                
        self.api.update_program_blacklist(self.get_program(), blacklist)
        
    def load_config(self):
        with open(os.path.expanduser(CONFIG_FILE)) as json_file:
            self.config = json.load(json_file)

    def save_config(self):
        with open(os.path.expanduser(CONFIG_FILE), 'w') as outfile:
            json.dump(self.config, outfile)
            
    def listen_for_changes(self):
        self.api.listen_for_changes()

    def run(self):
        try:
            self.load_config()
        except Exception as err:
            pass

        if self.arguments['new']:
            self.new_program()

        if self.arguments['use']:
            self.use_program()

        if self.arguments['program']:
            if self.arguments['list']:
                return "\n".join(self.list_programs())

            if self.arguments['active']:
                return self.get_program()

            if self.arguments['scope']:
                return "\n".join(self.get_program_scope())

        if self.arguments['domains']:
            if self.arguments['<view>']:
                return "\n".join(self.list_documents_view("domain", self.arguments['<view>'], self.arguments['--all']))
            else:
                return "\n".join(self.list_domains(self.arguments['--all']))

        if self.arguments['domain']:
            if self.arguments['add']:
                if self.arguments['<domain>']:
                    self.add_domains(self.arguments['<domain>'])
                elif self.arguments['-']:
                    self.add_domains(sys.stdin.read().split('\n'))
            if self.arguments['remove']:
                if self.arguments['<domain>']:
                    self.remove_domains(self.arguments['<domain>'])
                elif self.arguments['-']:
                    self.remove_domains(sys.stdin.read().split('\n'))
            if self.arguments['update']:
                if self.arguments['<domain>']:
                    self.update_domains(self.arguments['<domain>'])
                elif self.arguments['-']:
                    self.update_domains(sys.stdin.read().split('\n'))

        if self.arguments['ips']:
            if self.arguments['<view>']:
                return "\n".join(self.list_documents_view("ip", self.arguments['<view>'], self.arguments['--all']))
            return "\n".join(self.list_ips(self.arguments['--all']))

        if self.arguments['ip']:
            if self.arguments['add']:
                if self.arguments['<ip>']:
                    self.add_ips(self.arguments['<ip>'])
                elif self.arguments['-']:
                    self.add_ips(sys.stdin.read().split('\n'))
            if self.arguments['remove']:
                if self.arguments['<ip>']:
                    self.remove_ips(self.arguments['<ip>'])
                elif self.arguments['-']:
                    self.remove_ips(sys.stdin.read().split('\n'))
            if self.arguments['update']:
                if self.arguments['<ip>']:
                    self.update_ips(self.arguments['<ip>'])
                elif self.arguments['-']:
                    self.update_ips(sys.stdin.read().split('\n'))

        if self.arguments['inscope']:
            if self.arguments['add']:
                if self.arguments['<element>']:
                    self.add_inscope(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.add_inscope(sys.stdin.read().split('\n'))
            if self.arguments['remove']:
                if self.arguments['<element>']:
                    self.remove_inscope(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.remove_inscope(sys.stdin.read().split('\n'))
                    
        if self.arguments['outscope']:
            if self.arguments['add']:
                if self.arguments['<element>']:
                    self.add_outscope(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.add_outscope(sys.stdin.read().split('\n'))
            if self.arguments['remove']:
                if self.arguments['<element>']:
                    self.remove_outscope(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.remove_outscope(sys.stdin.read().split('\n'))

        if self.arguments['blacklist']:
            if self.arguments['add']:
                if self.arguments['<element>']:
                    self.add_blacklist(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.add_blacklist(sys.stdin.read().split('\n'))
            if self.arguments['remove']:
                if self.arguments['<element>']:
                    self.remove_blacklist(self.arguments['<element>'])
                elif self.arguments['-']:
                    self.remove_blacklist(sys.stdin.read().split('\n'))
                    
        if self.arguments['task']:
            if self.arguments['list']:
                return "\n".join(self.list_tasks())
            if self.arguments['remove']:
                return self.api.remove_document('task', {'key': self.arguments['<task>']})
            if self.arguments['add']:
                return "Not yet implemented..."
        
        if self.arguments['run']:
            return self.api.run_task(self.arguments['<task>'], self.get_program())
        
        if self.arguments['show']:
            return self.api.get_document(self.arguments['<document>'])

        if self.arguments['listen']:
            self.listen_for_changes()
            
        if self.arguments['alert']:
            if self.arguments['<message>']:
                self.api.create_alert(self.arguments['<message>'], self.get_program(), self.arguments['-s'])
            elif self.arguments['-']:
                for line in sys.stdin:
                    self.api.create_alert(line, self.get_program(), self.arguments['-s'])

        try:
            self.save_config()
        except Exception as err:
            pass
            
            
if __name__ == '__main__':
    arguments = docopt(__doc__, version='BBRF client 0.1b')
    bbrf = BBRFClient(arguments)
    result = bbrf.run()
    if result:
        print(result)