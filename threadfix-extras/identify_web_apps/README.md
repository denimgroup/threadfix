# Finding Web Applications and Populating ThreadFix #
## Introduction ##
Building and maintaining a portfolio of applications in an organization is a critical step in rolling out a successful software security program. Without an accurate and up-to-date application portfolio an organization's software attack surface is unknown and it is impossible to meaningfully defend an unknown attack surface. This script demonstrates a technical approach for identifying web applications on a network and loads those web applications into a Team on a ThreadFix server. This provides a starting point from which security analysts can attach additional application metadata and schedule scans and other assurance activities. This approach is not likely to provide a complete application portfolio because multiple application might be hosted on a single server and other applications may be hosted on other networks, but this script can help to provide a starting point.
## How It Works ##
The script works by scanning the network range provided on a number of known web server ports. When list hosts with open web server ports are identified, a screenshot of the suspected web application is taken, and the web application is created in the provided ThreadFix instance.s

## Running the Script ##
Usage: find_web_apps.py [options]

Options:

  -h, --help            show this help message and exit

  -n NETWORK, --network=NETWORK
                        Network to scan for web apps (nmap-style network
                        definition)

  -p PORTS, --ports=PORTS
                        Ports to check for web servers

  -k APIKEY, --apikey=APIKEY
                        API key for ThreadFix server

  -s SERVER, --server=SERVER
                        ThreadFix server

  -t TEAM, --team=TEAM  ThreadFix team to which apps will be added

  -v VERBOSE, --verbose=VERBOSE
                        Print verbose output

## References ##
The following projects/libraries were used to implement functionality in these examples:

* python-nmap - [http://xael.org/norman/python/python-nmap/](http://xael.org/norman/python/python-nmap/)
* webkit2png - [http://www.paulhammond.org/webkit2png/](http://www.paulhammond.org/webkit2png/)

