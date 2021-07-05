import os, sys, json, pytest, io
#currentdir = os.path.dirname(os.path.realpath(__file__))
#parentdir = os.path.dirname(currentdir)
sys.path.append("..")
from src import BBRFClient

with open(os.path.expanduser('~/.bbrf/config-test.json')) as f:
    conf = json.load(f)

def bbrf(cmd):
    return BBRFClient(cmd, conf).run()

def list_equals(a, b):
    diff = set(a) ^ set(b)
    return not diff and len(a) == len(b)

'''
bbrf ( new | use | disable | enable ) <program> [ -t key:value ]...
bbrf programs [ --show-disabled --show-empty-scope ]
'''
def test_program():
    bbrf('new test')
    # program without scope is not going to show up
    assert 'test' not in bbrf('programs')
    assert 'test' in bbrf('programs --show-empty-scope')  
    
    bbrf('disable test')
    assert [] == bbrf('programs')
    assert 'test' not in bbrf('programs --show-empty-scope')
    assert 'test' in bbrf('programs --show-empty-scope --show-disabled')
    
    bbrf('enable test')
    assert 'test' not in bbrf('programs')
    assert 'test' in bbrf('programs --show-empty-scope')
    
    bbrf('new testtag -t test:tag -t test2:tag2')
    assert bbrf('program active') == 'testtag'
    assert json.loads(bbrf('show testtag'))['tags']['test'] == 'tag'
    assert json.loads(bbrf('show testtag'))['tags']['test2'] == 'tag2'

def test_program_special_chars():
    bbrf('new test/weird&char?')
    # program without scope is not going to show up
    assert 'test/weird&char?' not in bbrf('programs')
    assert 'test/weird&char?' in bbrf('programs --show-empty-scope')
    bbrf('use test/weird&char?')
    bbrf('program update test/weird&char? -t test:tagupdated -t test2:tagupdated2')
    bbrf('inscope add *.weird.com')
    bbrf('domain add sub.weird.com')
    assert 'sub.weird.com' in bbrf('domains')
    bbrf('domain remove sub.weird.com')
    bbrf('inscope remove *.weird.com')
    
    
def test_program_use():
    bbrf('use test')
    assert bbrf('program active') == 'test'
    bbrf('use testtag')
    assert bbrf('program active') == 'testtag'
    with pytest.raises(Exception):
        bbrf('use notexist')
    
'''
bbrf programs where <tag_name> is [ before | after ] <value>
'''
def test_programs_where():
    assert 'testtag' in bbrf('programs where test is tag --show-empty-scope')
    assert 'testtag' in bbrf('programs where test2 is tag2 --show-empty-scope')
    assert 'testtag' in bbrf('programs where test is before tagzzz --show-empty-scope')
    assert 'testtag' not in bbrf('programs where test is after tagZZZ --show-empty-scope')
    assert 'testtag' not in bbrf('programs where test is before aaatag --show-empty-scope')
    assert 'testtag' in bbrf('programs where test is after aaatag --show-empty-scope')
    
'''
bbrf program ( active | update ( <program>... | - ) -t key:value... [--append-tags])
'''
def test_program_update_tags():
    bbrf('program update testtag -t test:tagupdated -t test2:tagupdated2')
    assert json.loads(bbrf('show testtag'))['tags']['test'] == 'tagupdated'
    bbrf('program update testtag -t test:tagupdated -t test:testarray')
    assert list_equals(json.loads(bbrf('show testtag'))['tags']['test'], ['tagupdated','testarray'])
    bbrf('program update testtag -t test:tagone')
    bbrf('program update testtag -t test:tagtwo --append-tags')
    assert list_equals(json.loads(bbrf('show testtag'))['tags']['test'], ['tagone','tagtwo'])
    bbrf('program update testtag -t test:tagone -t test:tagtwo')
    bbrf('program update testtag -t test:tagthree --append-tags')
    assert list_equals(json.loads(bbrf('show testtag'))['tags']['test'], ['tagone','tagtwo','tagthree'])

'''
bbrf ( inscope | outscope ) ( add | remove ) ( - | <element>... ) [ -p <program> ]
bbrf scope filter ( in | out ) [ (--wildcard [--top] ) ] [ ( -p <program> ) | ( --all [--show-disabled] ) ]
'''
def test_scope():
    bbrf('use test')
    bbrf('inscope add *.example.com')  
    bbrf('inscope add *.sub.example.com *.dev.example.com')
    assert list_equals(bbrf('scope in'), ['*.example.com', '*.sub.example.com', '*.dev.example.com'])
    
    bbrf('inscope remove *.dev.example.com')
    assert list_equals(bbrf('scope in'), ['*.example.com', '*.sub.example.com'])
    assert list_equals(bbrf('scope in --wildcard'), ['example.com', 'sub.example.com'])
    assert list_equals(bbrf('scope in --wildcard --top'), ['example.com'])
    
    bbrf('inscope add *.example.co.uk -p testtag')  
    bbrf('inscope add *.sub.example.co.uk *.dev.example.co.uk -p testtag')
    assert list_equals(bbrf('scope in -p testtag'), ['*.example.co.uk', '*.sub.example.co.uk', '*.dev.example.co.uk'])
    bbrf('inscope remove *.dev.example.co.uk -p testtag')
    assert list_equals(bbrf('scope in -p testtag'), ['*.example.co.uk', '*.sub.example.co.uk'])
    
    bbrf('outscope add *.dev.example.com')
    assert bbrf('scope out') == ['*.dev.example.com']
    assert bbrf('scope out --wildcard') == ['dev.example.com']
    assert bbrf('scope out --wildcard --top') == ['dev.example.com']
    bbrf('outscope add sub.dev.example.com')
    assert bbrf('scope out --wildcard --top') == ['dev.example.com']
    
    assert list_equals(bbrf('scope in --all'), [
        '*.example.com',
        '*.sub.example.com',
        '*.example.co.uk',
        '*.sub.example.co.uk',
    ])
    
    bbrf('disable testtag')
    assert list_equals(bbrf('scope in --all'), [
        '*.example.com',
        '*.sub.example.com',
    ])
    # TODO: this is inconsistent behaviour, and returns ONLY
    # disabled programs. See https://github.com/honoki/bbrf-client/issues/47
    assert list_equals(bbrf('scope in --all --show-disabled'), [
        '*.example.com',
        '*.sub.example.com',
        '*.example.co.uk',
        '*.sub.example.co.uk',
    ])
    bbrf('enable testtag')

    # test URL scopes
    bbrf('inscope add http://url.example.com/ https://url2.example.com')
    assert 'url.example.com' in bbrf('scope in')
    assert 'url2.example.com' in bbrf('scope in')
    bbrf('outscope add http://URL3.EXaMPLe.cOM/')
    assert 'url3.example.com' in bbrf('scope out')
    
def test_scope_filter(monkeypatch):
    bbrf('use test')
    monkeypatch.setattr('sys.stdin', io.StringIO('one.example.com\ntwo.example.com\nsub.dev.example.com'))
    assert list_equals(bbrf('scope filter in'), ['one.example.com', 'two.example.com'])
    monkeypatch.setattr('sys.stdin', io.StringIO('one.example.com\ntwo.example.com\nsub.dev.example.com'))
    assert list_equals(bbrf('scope filter out'), ['sub.dev.example.com'])
    
    monkeypatch.setattr('sys.stdin', io.StringIO('''
one.example.com
two.example.com
sub.dev.example.com
one.example.co.uk
two.example.co.uk
sub.dev.example.co.uk
'''))
    assert list_equals(bbrf('scope filter in --all'), ['one.example.com', 'two.example.com','one.example.co.uk', 'two.example.co.uk', 'sub.dev.example.co.uk'])
    monkeypatch.setattr('sys.stdin', io.StringIO('''
one.example.com
two.example.com
sub.dev.example.com
one.example.co.uk
two.example.co.uk
sub.dev.example.co.uk
'''))
    assert list_equals(bbrf('scope filter out --all'), ['sub.dev.example.com'])
    
'''
bbrf domain ( add | remove | update ) ( - | <domain>... ) [ -p <program> -s <source> --show-new ( -t key:value... [--append-tags] ) ]
bbrf domains [ --view <view> ( -p <program> | ( --all [--show-disabled] ) ) ]
'''
def test_domains(monkeypatch):
    assert bbrf('domains') == []
    
    # test adding and tagging
    bbrf('domain add one.example.com two.example.com three.example.com')
    assert list_equals(bbrf('domains'), ['one.example.com','two.example.com','three.example.com'])
    bbrf('domain add four.example.com:4.4.4.4')
    assert list_equals(bbrf('domains'), ['one.example.com','two.example.com','three.example.com', 'four.example.com'])
    bbrf('domain update one.example.com -t tagging:test_domains')
    assert json.loads(bbrf('show one.example.com'))['tags']['tagging'] == 'test_domains'
    bbrf('domain update one.example.com -t tagging:test_domains -t tagging:array')
    assert list_equals(json.loads(bbrf('show one.example.com'))['tags']['tagging'], ['test_domains', 'array'])
    bbrf('domain update one.example.com -t tagging:append --append-tags')
    assert list_equals(json.loads(bbrf('show one.example.com'))['tags']['tagging'], ['test_domains', 'array', 'append'])
    bbrf('domain update one.example.com -t tagging:overwrite')
    assert json.loads(bbrf('show one.example.com'))['tags']['tagging'] == 'overwrite'
    
    # test domains through input pipe
    monkeypatch.setattr('sys.stdin', io.StringIO('''
pipe1.example.com
pipe2.example.com
pipe3.dev.example.com
'''))
    bbrf('domain add -')
    assert list_equals(bbrf('domains'), ['one.example.com','two.example.com','three.example.com', 'four.example.com', 'pipe1.example.com', 'pipe2.example.com'])
    monkeypatch.setattr('sys.stdin', io.StringIO('''
pipe1.example.com
pipe2.example.com
pipe3.dev.example.com
'''))
    bbrf('domain remove -')
    assert list_equals(bbrf('domains'), ['one.example.com','two.example.com','three.example.com', 'four.example.com'])
    
    # test ips
    assert list_equals(json.loads(bbrf('show four.example.com'))['ips'], ['4.4.4.4'])
    bbrf('domain update four.example.com:4.4.4.4,4.4.4.5,4.4.4.6')
    assert list_equals(json.loads(bbrf('show four.example.com'))['ips'], ['4.4.4.4', '4.4.4.5','4.4.4.6'])
    bbrf('domain update four.example.com:4.4.4.4,4.4.4.5,4.4.4.6 four.example.com:4.4.4.4,4.4.4.7 -s pytest')
    assert list_equals(json.loads(bbrf('show four.example.com'))['ips'], ['4.4.4.4', '4.4.4.5','4.4.4.6','4.4.4.7'])
    
    # test source
    assert json.loads(bbrf('show four.example.com'))['source'] == 'pytest'
    
    # test --show-new for new and updated domains
    assert bbrf('domain add five.example.com --show-new -s pytest') == ['[NEW] five.example.com']
    assert json.loads(bbrf('show five.example.com'))['source'] == 'pytest'
    assert bbrf('domain update five.example.com -n') == None
    assert bbrf('domain update five.example.com:5.5.5.5 -n') == ['[UPDATED] five.example.com']
    assert bbrf('domain update five.example.com:5.5.5.5 -n') == None
    assert bbrf('domain update five.example.com:5.5.5.5 -n -s updated') == ['[UPDATED] five.example.com']
    
    # test remove
    bbrf('domain remove four.example.com five.example.com')
    assert list_equals(bbrf('domains'), ['one.example.com','two.example.com','three.example.com'])
    
    

'''
bbrf domains where <tag_name> is [ before | after ] <value> [ -p <program> | ( --all [--show-disabled] ) ]
'''
def test_domains_where():
    assert list_equals(bbrf('domains'), ['one.example.com','two.example.com','three.example.com'])
    bbrf('domain add four.example.com:4.4.4.4')
    
    assert list_equals(bbrf('domains where ip is 4.4.4.4'), ['four.example.com'])
    assert 'four.example.com' in bbrf('domains where ip is before 4.4.4.4ZZZ')
    assert 'four.example.com' not in bbrf('domains where ip is before 1.1.1.1')
    assert 'four.example.com' in bbrf('domains where ip is after 4.4.4.0')
    assert 'four.example.com' not in bbrf('domains where ip is after 4.4.4.9')
    
    
    assert list_equals(bbrf('domains where tagging is overwrite'), ['one.example.com'])
    assert 'one.example.com' in bbrf('domains where tagging is before overwriteZZZ')
    assert 'one.example.com' not in bbrf('domains where tagging is before overwritA')
    assert 'one.example.com' in bbrf('domains where tagging is after overwrita')
    assert 'one.example.com' not in bbrf('domains where tagging is after overwritZ')

def test_domains_underscore():
    bbrf('domain add _one.example.com _two.example.com')
    assert '_one.example.com' in bbrf('domains')
    assert '_two.example.com' in bbrf('domains')
    assert bbrf('domain add _three.example.com:3.0.3.0 -n') == ['[NEW] _three.example.com']
    assert bbrf('domains where ip is 3.0.3.0') == ['_three.example.com']
    assert bbrf('domain update _three.example.com:4.0.4.0 -n') == ['[UPDATED] _three.example.com']
    assert bbrf('domain remove _three.example.com -n') == ['[DELETED] _three.example.com']
    bbrf('domain remove _one.example.com _two.example.com')
    assert '_one.example.com' not in bbrf('domains')
    assert '_two.example.com' not in bbrf('domains')

'''
bbrf ips [ --filter-cdns ( -p <program> | ( --all [--show-disabled] ) ) ]
'''
def test_ips(monkeypatch):
    assert bbrf('ips') == []
    # test adding and tagging
    bbrf('ip add 1.1.1.1 2.2.2.2 3.3.3.3')
    assert list_equals(bbrf('ips'), ['1.1.1.1','2.2.2.2','3.3.3.3'])
    bbrf('ip add 4.4.4.4:four.example.com')
    assert list_equals(bbrf('ips'), ['1.1.1.1','2.2.2.2','3.3.3.3', '4.4.4.4'])
    bbrf('ip update 1.1.1.1 -t tagging:test_domains')
    assert json.loads(bbrf('show 1.1.1.1'))['tags']['tagging'] == 'test_domains'
    bbrf('ip update 1.1.1.1 -t tagging:test_domains -t tagging:array')
    assert list_equals(json.loads(bbrf('show 1.1.1.1'))['tags']['tagging'], ['test_domains', 'array'])
    bbrf('ip update 1.1.1.1 -t tagging:append --append-tags')
    assert list_equals(json.loads(bbrf('show 1.1.1.1'))['tags']['tagging'], ['test_domains', 'array', 'append'])
    bbrf('ip update 1.1.1.1 -t tagging:overwrite')
    assert json.loads(bbrf('show 1.1.1.1'))['tags']['tagging'] == 'overwrite'
    
    # test ips through input pipe
    monkeypatch.setattr('sys.stdin', io.StringIO('''
11.11.11.11
22.22.22.22
33.33.33.33
'''))
    bbrf('ip add -')
    assert list_equals(bbrf('ips'), ['1.1.1.1','2.2.2.2','3.3.3.3', '4.4.4.4', '11.11.11.11', '22.22.22.22', '33.33.33.33'])
    monkeypatch.setattr('sys.stdin', io.StringIO('''
11.11.11.11
22.22.22.22
33.33.33.33
'''))
    bbrf('ip remove -')
    assert list_equals(bbrf('ips'), ['1.1.1.1','2.2.2.2','3.3.3.3','4.4.4.4'])
    
    # test domains
    assert list_equals(json.loads(bbrf('show 4.4.4.4'))['domains'], ['four.example.com'])
    bbrf('ip update 4.4.4.4:four.example.com,four2.example.com,four3.example.com')
    assert list_equals(json.loads(bbrf('show 4.4.4.4'))['domains'], ['four.example.com', 'four2.example.com','four3.example.com'])
    bbrf('ip update 4.4.4.4:four4.example.com,four5.example.com 4.4.4.4:four6.example.com,four7.example.com -s pytest')
    assert list_equals(json.loads(bbrf('show 4.4.4.4'))['domains'], ['four.example.com', 'four2.example.com','four3.example.com','four4.example.com', 'four5.example.com','four6.example.com','four7.example.com'])
    
    # test source
    assert json.loads(bbrf('show 4.4.4.4'))['source'] == 'pytest'
    
    # test --show-new for new and updated domains
    assert bbrf('ip add 5.5.5.5 --show-new -s pytest') == ['[NEW] 5.5.5.5']
    assert json.loads(bbrf('show 5.5.5.5'))['source'] == 'pytest'
    assert bbrf('ip update 5.5.5.5 -n') == None
    assert bbrf('ip update 5.5.5.5:five.example.com -n') == ['[UPDATED] 5.5.5.5']
    assert bbrf('ip update 5.5.5.5:five.example.com -n') == None
    assert bbrf('ip update 5.5.5.5:five.example.com -n -s updated') == ['[UPDATED] 5.5.5.5']
    
    # test remove
    bbrf('ip remove 4.4.4.4 5.5.5.5')
    assert list_equals(bbrf('ips'), ['1.1.1.1','2.2.2.2','3.3.3.3'])

'''
bbrf ips where <tag_name> is [ before | after ] <value> [ -p <program> | ( --all [--show-disabled] ) ]
'''
def test_ips_where():
    assert list_equals(bbrf('ips'), ['1.1.1.1','2.2.2.2','3.3.3.3'])
    bbrf('ip add 4.4.4.4:four.example.com')
    
    assert list_equals(bbrf('ips where domain is four.example.com'), ['4.4.4.4'])
    assert '4.4.4.4' in bbrf('ips where domain is before four.example.coZ')
    assert '4.4.4.4' not in bbrf('ips where domain is before AAAA.example.com')
    assert '4.4.4.4' in bbrf('ips where domain is after four.example.aaa')
    assert '4.4.4.4' not in bbrf('ips where domain is after four.example.ZZZ')
    
    
    assert list_equals(bbrf('ips where tagging is overwrite'), ['1.1.1.1'])
    assert '1.1.1.1' in bbrf('ips where tagging is before overwriteZZZ')
    assert '1.1.1.1' not in bbrf('ips where tagging is before overwritA')
    assert '1.1.1.1' in bbrf('ips where tagging is after overwrita')
    assert '1.1.1.1' not in bbrf('ips where tagging is after overwritZ')

'''
bbrf urls [ -d <hostname> | ( -p <program> | ( --all [--show-disabled] ) ) ] [--with-query]
'''
def test_urls():
    assert list_equals(bbrf('urls'), [])
    
    # plain http
    bbrf('url add http://one.example.com/one')
    bbrf('url add http://two.example.com/two http://three.example.com/three')
    assert list_equals(bbrf('urls'), [
        'http://one.example.com/one',
        'http://two.example.com/two',
        'http://three.example.com/three'
    ])
    
    # https
    bbrf('url add http://three.example.com/1 http://three.example.com/2 http://three.example.com/3 -t protocol:http')
    bbrf('url add https://three.example.com/1 https://three.example.com/2 https://three.example.com/3 -t protocol:https')
    # with query strings
    bbrf('url add http://three.example.com/query?one=two&three=four')
    bbrf('url add http://three.example.com/query?five=six')
    bbrf('url add https://three.example.com:8080/url?some=what')
    # relative path with specified domain
    bbrf('url add /relative -d three.example.com')
    
    # when port :80 or :443 are explicitly set in the URL, they need to be removed
    # so we don't duplicate value where port is not set!
    bbrf('url add http://three.example.com:80/1 https://port.example.com:443/port https://port.example.com/port')
    
    assert list_equals(bbrf('urls'), [
        'http://one.example.com/one',
        'http://two.example.com/two',
        'http://three.example.com/three',
        'http://three.example.com/1',
        'http://three.example.com/2',
        'http://three.example.com/3',
        #https
        'https://three.example.com/1',
        'https://three.example.com/2',
        'https://three.example.com/3',
        #querystrings
        'http://three.example.com/query',
        'https://three.example.com:8080/url',
        #relative
        'http://three.example.com/relative',
        
        # explicit ports:
        # https://port.example.com:443/port should not be listed
        # http://three.example.com:80/1 should not be listed
        'https://port.example.com/port'
    ])
    
    # including query strings
    assert list_equals(bbrf('urls -q'), [
        'http://one.example.com/one',
        'http://two.example.com/two',
        'http://three.example.com/three',
        'http://three.example.com/1',
        'http://three.example.com/2',
        'http://three.example.com/3',
        #https
        'https://three.example.com/1',
        'https://three.example.com/2',
        'https://three.example.com/3',
        #querystrings
        'http://three.example.com/query?one=two&three=four',
        'http://three.example.com/query?five=six',
        'https://three.example.com:8080/url?some=what',
        #relative
        'http://three.example.com/relative',
        # explicit ports:
        'https://port.example.com/port'
    ])
    
    # including status codes and content lengths
    bbrf('url add http://three.example.com/c 200 1234')
    assert 'http://three.example.com/c' in bbrf('urls')
    
'''
bbrf urls where <tag_name> is [ before | after ] <value> [ -p <program> | ( --all [--show-disabled] ) ]
'''
def test_urls_where():
    assert 'http://one.example.com/one' in bbrf('urls where hostname is one.example.com')
    assert 'https://three.example.com:8080/url' in bbrf('urls where port is 8080')
    
    assert 'http://three.example.com/1' in bbrf('urls where protocol is http')
    assert 'http://three.example.com/1' in bbrf('urls where protocol is after httA')
    assert 'http://three.example.com/1' not in bbrf('urls where protocol is after httpZZZ')
    assert 'http://three.example.com/1' in bbrf('urls where protocol is before httZ')
    assert 'http://three.example.com/1' not in bbrf('urls where protocol is before httA')

'''
bbrf url remove ( - | <url>... )
'''
def test_urls_remove(monkeypatch):
    bbrf('url remove https://three.example.com:8080/url')
    assert 'https://three.example.com:8080/url' not in bbrf('urls')
    monkeypatch.setattr('sys.stdin', io.StringIO('''
http://one.example.com/one
http://two.example.com/two
http://three.example.com/three
http://three.example.com/1
http://three.example.com/2
http://three.example.com/3
http://three.example.com/c
'''))
    bbrf('url remove -')
    assert list_equals(bbrf('urls'), [
        #https
        'https://three.example.com/1',
        'https://three.example.com/2',
        'https://three.example.com/3',
        #querystrings
        'http://three.example.com/query',
        #relative
        'http://three.example.com/relative',
        # explicit ports:
        'https://port.example.com/port'
    ])

'''
bbrf services [ -p <program> | ( --all [--show-disabled] ) ]
bbrf service add ( - | <service>... ) [ -s <source> -p <program> --show-new ( -t key:value... [ --append-tags ] ) ]
'''
def test_services():
    assert bbrf('services') == []
    bbrf('service add 1.1.1.1:11 2.2.2.2:22:ssh 3.3.3.3:33')
    assert bbrf('service add 3.3.3.3:33 -n') == None
    assert bbrf('service add 3.3.3.3:33:some -n') == ['[UPDATED] 3.3.3.3:33']
    assert bbrf('service add 3.3.3.3:33:some -n') == None
    assert bbrf('service add 3.3.3.3:33:some -n -s updated') == ['[UPDATED] 3.3.3.3:33']
    
    assert list_equals(bbrf('services'), [
        '1.1.1.1:11',
        '2.2.2.2:22',
        '3.3.3.3:33'
    ])
    
    bbrf('service add 1.1.1.1:11 -t tagging:test_services')
    assert json.loads(bbrf('show 1.1.1.1:11'))['tags']['tagging'] == 'test_services'
    bbrf('service add 1.1.1.1:11 -t tagging:test_services -t tagging:array')
    assert list_equals(json.loads(bbrf('show 1.1.1.1:11'))['tags']['tagging'], ['test_services', 'array'])
    bbrf('service add 1.1.1.1:11 -t tagging:append --append-tags')
    assert list_equals(json.loads(bbrf('show 1.1.1.1:11'))['tags']['tagging'], ['test_services', 'array', 'append'])
    bbrf('service add 1.1.1.1:11 -t tagging:overwrite')
    assert json.loads(bbrf('show 1.1.1.1:11'))['tags']['tagging'] == 'overwrite'

'''
bbrf services where <tag_name> is [ before | after ] <value> [ -p <program> | ( --all [--show-disabled] ) ]
'''
def test_services_where():
    assert '1.1.1.1:11' in bbrf('services where ip is 1.1.1.1')
    assert '1.1.1.1:11' in bbrf('services where port is 11')
    assert '2.2.2.2:22' in bbrf('services where service is ssh')
    assert '3.3.3.3:33' in bbrf('services where service is some')
    
    assert '1.1.1.1:11' in bbrf('services where tagging is overwrite')
    assert '1.1.1.1:11' in bbrf('services where tagging is after overwritA')
    assert '1.1.1.1:11' not in bbrf('services where tagging is after overwriteZZZ')
    assert '1.1.1.1:11' in bbrf('services where tagging is before overwritZ')
    assert '1.1.1.1:11' not in bbrf('services where tagging is before overwritA')

'''
bbrf service remove ( - | <service>... )
'''
def test_service_remove(monkeypatch):
    bbrf('service remove 1.1.1.1:11')
    assert '1.1.1.1:11' not in bbrf('services')
    monkeypatch.setattr('sys.stdin', io.StringIO('''
1.1.1.1:11
1.1.1.1:11
2.2.2.2:22
3.3.3.3:33
'''))
    bbrf('service remove -')
    assert list_equals(bbrf('services'), [])

'''
bbrf blacklist ( add | remove ) ( - | <element>... ) [ -p <program> ]
'''
def test_blacklist():
    bbrf('use test')
    bbrf('blacklist add blacklist.example.com')
    bbrf('domain add blacklist.example.com')
    assert 'blacklist.example.com' not in bbrf('domains')
    
    bbrf('blacklist remove blacklist.example.com')
    bbrf('domain add blacklist.example.com')
    assert 'blacklist.example.com' in bbrf('domains')
    
    bbrf('blacklist add 9.9.9.9')
    bbrf('domain add blacklistip.example.com:9.9.9.9')
    assert 'blacklistip.example.com' not in bbrf('domains')

'''
bbrf agent ( list | ( register | remove ) <agent>... | gateway [ <url> ] )
'''
def test_agent():
    assert bbrf('agent list') == []
    bbrf('agent register testagent')
    assert bbrf('agent list') == ['testagent']
    bbrf('agent register testagent2')
    bbrf('agent remove testagent')
    assert bbrf('agent list') == ['testagent2']
    bbrf('agent gateway http://localhost/gateway-test')
    assert bbrf('agent gateway') == 'http://localhost/gateway-test'
    
'''
bbrf agents
'''
def test_agents():
    assert bbrf('agents') == ['testagent2']

'''
bbrf run <agent> [ -p <program> ]
'''
pass

'''
bbrf listen
'''
pass

'''
bbrf alert ( - | <message> ) [ -s <source> ]
'''
pass

'''
bbrf tags [<name>] [ -p <program> | --all ]
'''
def test_tags():
    assert list_equals(bbrf('tags'), [
        'tagging',
        'protocol'
    ])
    
    assert list_equals(bbrf('tags --all'), [
        'test', # tag on program test
        'test2', # tag on proram test
        'tagging',
        'protocol'
    ])
    
    assert list_equals(bbrf('tags protocol'), [
        'https://three.example.com/1 https',
        'https://three.example.com/2 https',
        'https://three.example.com/3 https',
    ])
    assert list_equals(bbrf('tags tagging'), [
        '1.1.1.1 overwrite',
        'one.example.com overwrite',
    ])

'''
bbrf server upgrade
'''
def test_upgrade():
    # not yet sure how to test this here
    pass