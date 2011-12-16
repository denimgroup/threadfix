##############################################################################
##
##     Copyright (c) 2009-2011 Denim Group, Ltd.
##
##     The contents of this file are subject to the Mozilla Public License
##     Version 1.1 (the "License"); you may not use this file except in
##     compliance with the License. You may obtain a copy of the License at
##     http://www.mozilla.org/MPL/
##
##     Software distributed under the License is distributed on an "AS IS"
##     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
##     License for the specific language governing rights and limitations
##     under the License.
##
##     The Original Code is Vulnerability Manager.
##
##     The Initial Developer of the Original Code is Denim Group, Ltd.
##     Portions created by Denim Group, Ltd. are Copyright (C)
##     Denim Group, Ltd. All Rights Reserved.
##
##     Contributor(s): Denim Group, Ltd.
##
##############################################################################
# reports.rb

=begin
Dependencies:
	SOAP Library
	Base64 Library
	In the same directory, there must be a Netsparker file with the name netsparker.xml

Usage:
	This class includes methods to 
		1. Parse a Netsparker scan (or any scan with <vulnerability> tags into a hash with integers => vulnerability text
		2. construct the text for a scan given a date, an array of integers to run through the hash from 1
		
	It then goes on to construct 3 such scans and upload them using RPC. 
	These methods can be used from other files too by including this one.
	
=end

require 'rubygems'
require 'Base64'
require 'soap/wsdlDriver'

SCANNER_NAME = 'Mavituna Security Netsparker'
API_KEY  = ARGV[0]
APP_NAME = ARGV[1]

def get_driver
	wsdl_url = 'http://localhost:8080/services/RPCService?WSDL'
	return SOAP::WSDLDriverFactory.new(wsdl_url).create_rpc_driver
end

def base64_encode string
	Base64.encode64(string).gsub("\n", '')
end

# build map of integers to corresponding vuln texts
def parse_netsparker_file
	current_vuln = ''
	vulns_hash = {}
	in_vuln = false
	number = 1

	File.readlines('netsparker.xml').each do |line|
		if line.include? '<vulnerability'
			in_vuln = true
		end
		
		if in_vuln
			current_vuln << line
		end	
		
		if line.include? '</vulnerability>'
			vulns_hash[number] = current_vuln
			current_vuln = ''
			number += 1
			in_vuln = false
		end
	end

	print "Got #{number} vulns.\n"
	vulns_hash
end

# build simulated scan file. pass in a date and an array of keys for vulns to include.
def construct_scan date, vuln_number_array, vuln_hash = parse_netsparker_file

	preamble_before_date = '<?xml version="1.0" encoding="utf-8" ?>
	<?xml-stylesheet href="vulnerabilities-list.xsl" type="text/xsl" ?>
	<netsparker generated="'

	preamble_after_date = '">
		<target>
			<url>http://tftarget/demo/</url>
			<scantime>230</scantime>
		</target>'
		
	ending_tags = '</netsparker>'
	
	output = preamble_before_date + date + preamble_after_date
	
	vuln_number_array.each do |number|
		output << vuln_hash[number].to_s
	end
	
	output += ending_tags
	
	base64_encode(output)
end

driver = get_driver

app_id = driver.createApplication(API_KEY, APP_NAME, "http://url", 3)[0]
print "Application ID      -> #{app_id}\n"

channel_id = driver.addChannel(API_KEY, SCANNER_NAME, app_id)[0]
print "Channel ID          -> #{channel_id}\n"

hash = parse_netsparker_file
scans = []

scans << construct_scan('4/13/2011 3:04:46 PM', (0..15).to_a, hash)
scans << construct_scan('5/13/2011 6:34:63 PM', (0..10).to_a, hash)
scans << construct_scan('6/13/2011 1:30:15 PM', (0..5).to_a, hash)

scans.each do |scan|
	scan_id = driver.runScan(USERNAME, PASSWORD, channel_id, scan, "test.txt")[0]
	print "Scan ID             -> #{scan_id}\n"
end

