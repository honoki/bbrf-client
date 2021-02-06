# Usage

The `docopt` section at the top of [bbrf.py](../bbrf.py) will always contain the latest documentation. Or type `bbrf -h` to view the documentation in your terminal window:

```
Usage:
  bbrf (new|use|disable|enable) <program> [ -t <tag>... ]
  bbrf programs [--show-disabled]
  bbrf program (list [--show-disabled] | [active])
  bbrf domains [--view <view> (-p <program> | --all)]
  bbrf domains where <tag_name> is [before | after] <value> [-p <program> | --all]
  bbrf domain (add|remove|update) ( - | <domain>...) [-p <program> -s <source> --show-new -t <tag>...]
  bbrf ips [ --filter-cdns (-p <program> | --all)]
  bbrf ips where <tag_name> is [before | after] <value> [-p <program> | --all]
  bbrf ip (add|remove|update) ( - | <ip>...) [-p <program> -s <source> --show-new -t <tag>...]
  bbrf scope (in|out) [(--wildcard [--top])] ([-p <program>] | (--all [--show-disabled]))
  bbrf (inscope|outscope) (add|remove) (- | <element>...) [-p <program>]
  bbrf urls (-d <hostname> | [-p <program>] | --all)
  bbrf urls where <tag_name> is [before | after] <value> [-p <program> | --all]
  bbrf url add ( - | <url>...) [-d <hostname> -s <source> -p <program> --show-new -t <tag>...]
  bbrf url remove ( - | <url>...)
  bbrf services [-p <program> | --all]
  bbrf services where <tag_name> is [before | after] <value> [-p <program> | --all]
  bbrf service add ( - | <service>...) [-s <source> -p <program> --show-new -t <tag>...]
  bbrf service remove ( - | <service>...)
  bbrf blacklist (add|remove) ( - | <element>...) [-p <program>]
  bbrf agents
  bbrf agent ( list | (register | remove) <agent> | gateway [<url>])
  bbrf run <agent> [-p <program>]
  bbrf show <document>
  bbrf listen
  bbrf alert ( - | <message>) [-s <source>]

Options:
  -h --help     Show this screen.
  -p <program>  Select a program to limit the command to. Not required when the command "use" has been run before.
  -t <tag>      Specify one or more custom properties (tags) to add to your document. Format as key:value
  -s <source>   Provide an optional source string to store information about the source of the modified data.
  -v --version  Show the program version
  -d <hostname> Explicitly specify the hostname of a URL in case of relative paths
  --show-new    Print new unique values that were added to the database, and didn't already exist
  --all         Specify to get information across all programs. Incompatible with the -p flag
```

## Examples

Create and configure a new program with a defined scope:

[![asciicast](https://asciinema.org/a/6GWe0GxUnFhTmPIqzh97iA6g5.png)](https://asciinema.org/a/6GWe0GxUnFhTmPIqzh97iA6g5)

When adding domains to your database, note that `bbrf` will automatically remove duplicates and check against the defined scope.

[![asciicast](https://asciinema.org/a/SxDNPfB7QDa1Q9etSEFhSoe28.png)](https://asciinema.org/a/SxDNPfB7QDa1Q9etSEFhSoe28)

Integrate with recon tools you already know and love:

[![asciicast](https://asciinema.org/a/ItX9xMdTuUm02G40rNNN4YUFz.png)](https://asciinema.org/a/ItX9xMdTuUm02G40rNNN4YUFz)

Resolve domains with [`massdns`](https://github.com/blechschmidt/massdns), format with `awk`, and save results with `bbrf`:

```bash
bbrf domains --view unresolved | \
    massdns -t A -o Snlqr -r resolvers.txt | \
    # reformat output to put query and response on the same line for grepping
    awk -v FS="\n" -v RS="\n\n" '{print $1";"$2}' | \
    # pipe output to multiple greps
    tee \
      >(grep ' A ' | awk -F' ' '{print $4":"$7}' | bbrf domain update -) \
      >(grep ' A ' | awk -F' ' '{print $7":"$4}' | bbrf ip add - -s massdns) \
      >(grep ' A ' | awk -F' ' '{print $7":"$4}' | bbrf ip update -);
```
You can find the a updated resolver.txt file from [`here`](https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt)

## URLs

BBRF will help you manage your URLs, and store their hostname, port, status code and content length for you:

```bash
bbrf url add 'https://www.example.com:8443/a' 'http://www.example.com/b' 'http://www.example.com/c 200 1234'
```

Two formats are accepted: `<url>` or `<url> <statuscode> <contentlength>` delimited by spaces.

The `<url>` can be absolute or relative. A relative URL will require the `-d <hostname>` flag to be specified or will be skipped. Whenever the `-d` flag is set, it will compare that with the hostname parsed from the URL, and skip the URL if they do not match.

Relative URLs and URLs that do not specify a scheme (`http://` or `https://`) will always be interpreted with scheme `http://`. If no port is found, ports 80 and 443 will be used as a default depending on the scheme.

The flag `--show-new` will print a list of new and updated URLs if they were added, or if their status code and/or content length were updated respectively:

```bash
cat urls.txt | bbrf url add - --show-new
[UPDATED] https://sub.example.com:8443/b
[NEW] http://www.example.com/a
[NEW] http://www.example.com/c
```

To view a list of stored URLs of your active program, simply use:

```bash
bbrf urls
``` 

Or, to return URLs belonging to a specific host:

```bash
bbrf urls -d www.example.com
``` 

To list URLs across all programs, run:

```bash
bbrf urls --all
```

## Listener

In order to process changes and alerts as they are pushed to the data store, you need to have an active listener running somewhere:

```bash
bbrf listen
```

This will start listening for changes on the CouchDB server and push notifications to your configured Slack instance. Note that this will fail e.g. when the bbrf server is temporarily unavailable or in case of certificate errors, so you may want to loop this to auto-start in case of issues.
