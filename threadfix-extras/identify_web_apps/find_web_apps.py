#!/usr/local/bin/python3

import nmap
from optparse import OptionParser

print("ThreadFix web application detection")

# Configure command line argument parsing

parser = OptionParser()
parser.add_option('-n', '--network', dest='network', help='Network to scan for web apps (nmap-style network definition)')
parser.add_option('-p', '--ports', dest='ports', help='Ports to check for web servers', default='80,443,8080,8443')
parser.add_option('-k', '--apikey', dest='apikey', help='API key for ThreadFix server')
parser.add_option('-s', '--server', dest='server', help='ThreadFix server', default='http://localhost:8080/threadfix/')
parser.add_option('-t', '--team', dest='team', help='ThreadFix team to which apps will be added')
parser.add_option('-v', '--verbose', dest='verbose', help='Print verbose output')

(options, args) = parser.parse_args()

# Run the nmap scan

print ('Starting nmap scan to identify web applications')

print ('Network to scan: {0}'.format(options.network))
print ('Ports to be checked for webservers: {0}'.format(options.ports))

nm = nmap.PortScanner()
nm.scan(options.network, options.ports)

print ('nmap scan completed')

hosts = nm.all_hosts()
for host in hosts:
	print ('Host identified: {0} has status {1}'.format(host, nm[host].state()))
	ports = nm[host]['tcp'].keys()
	for port in ports:
		if (options.verbose):
			print ('\tPort identified: {0} has status {1}'.format(port, nm[host]['tcp'][port]['state']))
		if (nm[host]['tcp'][port]['state'] == 'open'):
			print ('\tWebserver detected for host {0} with hostname {1} on port {2}'.format(host, nm[host].hostname(), port))
