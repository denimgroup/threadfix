#!/usr/local/bin/python3

import json
import nmap
from optparse import OptionParser
import os
import requests
from requests.exceptions import SSLError
from subprocess import call

#####
# Functions
#####

def take_screenshot(url_to_screenshot):
	ret_val = False;

	clean_screenshot_file()

	# shell_result = call(['webkit2png/webkit2png', '-F', '-o', 'threadfixscript', '--ignore-ssl-check', 'https://' + app_name], stdout=open(os.devnull, 'wb'), stderr=open(os.devnull, 'wb'))
	shell_result = call(['webkit2png/webkit2png', '-F', '-o', 'threadfixscript', '--ignore-ssl-check', url_to_screenshot])
	if (options.verbose):
		print ('\twebkit2png return code: ' + str(shell_result))

	if (os.path.isfile(screenshot_filename)):
		ret_val = True

	return ret_val;


def clean_screenshot_file():
	# Try to clean up the screenshot file
	try:
		os.remove(screenshot_filename)
	except:
		pass


#####
# Constants
#####

screenshot_filename = 'threadfixscript-full.png'


#####
# Main stuff
#####

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

if (options.verbose):
	print ('ThreadFix Server: {0}'.format(options.server))
	print ('Network: {0}'.format(options.network))
	print ('Ports: {0}'.format(options.ports))
	print ('ThreadFix Team Name: {0}'.format(options.team))

threadfix_rest_url = options.server + '/rest/'
	

# Run the nmap scan

print ('Starting nmap scan to identify web applications')

print ('Network to scan: {0}'.format(options.network))
print ('Ports to be checked for webservers: {0}'.format(options.ports))

nm = nmap.PortScanner()
nm.scan(options.network, options.ports)

print ('nmap scan completed')

print ('Creating ThreadFix team: {0}'.format(options.team))

# Check to see if the team already exists
payload = { 'apiKey': options.apikey, 'name': options.team }
r = requests.get(threadfix_rest_url + '/teams/lookup', params=payload)
if (options.verbose):
	print ('Raw response to team search: {0}'.format(r.text))
team_info = r.json()

try:
	team_id = team_info['id']
except KeyError:
	# Team doesn't exist. Must create and grab the ID
	if (options.verbose):
		print ('Team does not exist. Creating')
	payload = { 'apiKey': options.apikey, 'name': options.team }
	r = requests.post(threadfix_rest_url + '/teams/new', params=payload)
	team_info = r.json()
	team_id = team_info['id']

if (options.verbose):
	print ('Team ID is: {0}'.format(team_id))
	

hosts = nm.all_hosts()
for host in hosts:
	print ('Host identified: {0} has status {1}'.format(host, nm[host].state()))
	ports = nm[host]['tcp'].keys()
	for port in ports:
		if (options.verbose):
			print ('\tPort identified: {0} has status {1}'.format(port, nm[host]['tcp'][port]['state']))
		if (nm[host]['tcp'][port]['state'] == 'open'):
			print ('\tWebserver detected for host {0} with hostname {1} on port {2}'.format(host, nm[host].hostname(), port))

			if (nm[host].hostname() == ''):
				app_name = '{0}:{1}'.format(host, port)
			else:
				app_name = '{0}:{1}'.format(nm[host].hostname(), port)

			# Try to determine if the web server is running HTTP or HTTPS
			test_url = 'https://' + app_name + '/'

			try:
				test_request = requests.get(test_url, verify=False)
				if (options.verbose):
					print('\tHTTPS connection successful. Web server is running HTTPS')
				app_url = 'https://' + app_name + '/'
			except SSLError as e:
				if (options.verbose):
					print ('\tGot an SSLError. Apparently the web server is not running HTTPS')
				app_url = 'http://' + app_name + '/'

			if(options.verbose):
				print('\tApp name will be {0}, app URL will be: {1}'.format(app_name, app_url))

			# Create the new application in Threadfix
			payload = { 'apiKey': options.apikey, 'name': app_name, 'url': app_url }
			r = requests.post(threadfix_rest_url + '/teams/' + str(team_id) + '/applications/new', params=payload)
			new_app = r.json()
			try:
				app_id = new_app['id']
				print ('\tNew applicaiton created with id: {0}'.format(app_id))

				# Attach screenshot if we can get one
				result = take_screenshot(app_url)

				if(result):
					print ('\tGoing to upload screenshot for application {0}'.format(app_name))
					payload = { 'apiKey': options.apikey, 'filename': 'screenshot.png' }
					files = { 'file': open(screenshot_filename, 'rb') }
					r = requests.post(threadfix_rest_url + '/applications/' + str(app_id) + '/attachFile', params=payload, files=files)
					if (options.verbose):
						print('\t' + r.text)
				else:
					print ('\tUnable to get screenshot. Will not upload screenshot for application {0}'.format(app_name))
					
			except KeyError:
				print ('\tError when creating application: {0}'.format(new_app['message']))


