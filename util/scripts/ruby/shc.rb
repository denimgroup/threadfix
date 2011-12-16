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
# shc.rb
# Written by Mac Collins

=begin
Dependencies:
	Documented in the require calls.

Usage:
	This script does the following things:
		1. Parse arguments
		2. Reset WAF configuration so that it is correct and no rules are running (or the CRS is running)
		3. If desired, do an attack demo using automated IE
		4. Run initial scan with the desired scanner
		5. Create Threadfix objects through RPC calls
		6. If desired, view the scan in Threadfix
		7. Pull WAF rules from Threadfix
		8. Update the WAF with the new rules and reset
		9. If desired, run the second attack demo, which should no longer show the vulnerability.
		10. Run the scan again
		11. Upload the new results to Threadfix
		12. Upload the logs from the WAF to Threadfix
		13. If desired, point the browser at the closed vuln page for the application.
	
=end

require 'rubygems'
require 'soap/wsdlDriver'
require 'net/ssh'
require 'net/scp'
require 'skipfish_driver.rb'
require 'snort_driver.rb'
require 'mod_security_driver.rb'
require 'w3af_driver.rb'
require 'ie_driver.rb'

SNORT    = "Snort"
MOD_SEC  = "mod_security"
SKIPFISH = "Skipfish"
W3AF     = "w3af"
ORG_ID   = 3

# sample run
# ruby shc.rb -s skipfish -w mod_security -d deny -show_attack enable -show_threadfix enable -breaks enable -t vicnum -a "Vicnum" 

SENSOR_IP = "192.168.1.20"
APP_URL   = "http://url.com"

def exit
	print "Usage: ruby shc.rb -a application_name -s scanner_name -w WAF name -api api_key
				  [-d rule directive] [-t target app extension] 
				  [-show_attack enable attack demonstration] 
				  [-show_threadfix enable threadfix demonstration]
				  [-crs enable crs] 
				  [-breaks enable breaks]
				  [-server-reset disable reset]"
	Process.exit
end

def get_driver
	# the WSDL driver lets Ruby know the method signatures it can use.
	wsdl_url = 'http://localhost:8080/services/RPCService?WSDL'
	return SOAP::WSDLDriverFactory.new(wsdl_url).create_rpc_driver
end

def pause message = ""
	print "\n" + message
	print "Press Enter to continue.\n"
	break_line = STDIN.gets
end

# possible options = -api -a -s -t -d -w -ip -show_attack -show_threadfix -crs -breaks -server-reset
exit if ARGV.size == 0 || ((ARGV.size % 2) == 1)
	
arg_hash = eval("{\"#{ARGV.join("\",\"")}\"}")
exit if arg_hash["-a"].nil? || arg_hash["-s"].nil? || arg_hash["-w"].nil? || arg_hash["-api"].nil?

APP_NAME      = arg_hash["-a"]
WAF_NAME      = APP_NAME
scanner_name  = arg_hash["-s"]
waf_name      = arg_hash["-w"]
API_KEY       = arg_hash["-api"]

WAF_DIRECTIVE = !arg_hash["-d"].nil? ? arg_hash["-d"] : "drop"
TARGET_APP    = !arg_hash["-t"].nil? ? arg_hash["-t"] : "peruggia"

ATTACK_DEMO   = (!arg_hash["-show_attack"].nil? && arg_hash["-show_attack"] == "enable")
TF_DEMO       = (!arg_hash["-show_threadfix"].nil? && arg_hash["-show_threadfix"] == "enable")
CRS           = (!arg_hash["-crs"].nil? && arg_hash["-crs"] == "enable")
BREAKS        = (!arg_hash["-breaks"].nil? && arg_hash["-breaks"] == "enable")
SKIP_SERVER_RESET = (!arg_hash["-server-reset"].nil? && arg_hash["-server-reset"] == "disable")

scanner, waf = nil, nil

if scanner_name.downcase == SKIPFISH.downcase
	scanner = SkipfishDriver.new
	SCANNER_NAME = SKIPFISH
elsif scanner_name.downcase == W3AF.downcase
	scanner = W3afDriver.new
	SCANNER_NAME = W3AF
else
	exit
end

if waf_name.downcase == SNORT.downcase
	WAF_TYPE = SNORT
	waf = SnortDriver.new "mac", "password", "192.168.1.20", CRS
elsif waf_name.downcase == MOD_SEC.downcase
	WAF_TYPE = MOD_SEC
	waf = ModSecurityDriver.new "mac", "password", "192.168.1.20", CRS
else
	exit
end

URL      = waf.get_target_url
DEMO_URL = "http://#{URL}/peruggia/index.php/-->\">'>'\"<IMG SRC=http://www.hungry-hackers.com/wp-content/uploads/2010/09/xss1.jpg>"
browser  = (ATTACK_DEMO || TF_DEMO) ? IEDriver.new : nil
#browser.go_fullscreen unless browser.nil?

#-----------------------------------------------------------------------------
#                      Update WAF config & clear rules
#-----------------------------------------------------------------------------
unless SKIP_SERVER_RESET
	pause "About to update WAF config and clear rules.\n" if BREAKS

	print "Updating Server Configuration to #{WAF_TYPE}\n"
	waf.update_server_configuration

	waf.reroute_proxy "192.168.1.40" if WAF_TYPE == MOD_SEC
	
	start_time = Time.now

	print "Clearing #{WAF_TYPE} Rules\n"
	waf.update_rules_file ""

	waf.restart
end

#-----------------------------------------------------------------------------
#                              First Attack Demo
#-----------------------------------------------------------------------------
if ATTACK_DEMO
	pause "About to conduct first attack demo.\n" if BREAKS
	
	print "Conducting first attack demo.\n"
	browser.show
	browser.use_normally waf.get_target_url
	browser.attack waf.get_target_url
end

#-----------------------------------------------------------------------------
#                              Run Initial Scan
#-----------------------------------------------------------------------------
pause "About to run first #{scanner_name} scan.\n" if BREAKS

print "Running first #{scanner_name} scan.\n"
file_contents = scanner.scan 'output_dir2', URL, TARGET_APP
print "Finished first #{scanner_name} scan.\n"
#-----------------------------------------------------------------------------
#                    Setup Threadfix Objects and Upload Scan
#-----------------------------------------------------------------------------
pause "About to set up Threadfix objects and upload scan.\n" if BREAKS

# This driver uses camel case because it is the Java RPC object.
driver = get_driver

# To see all the traffic, uncomment this line (breaks on big files)
# driver.wiredump_dev = STDOUT

app_id = driver.createApplication(API_KEY, APP_NAME, APP_URL, ORG_ID)[0]
print "Application ID -> #{app_id}\n"

channel_id = driver.addChannel(API_KEY, SCANNER_NAME, app_id)[0]
print "Channel ID     -> #{channel_id}\n"

scan_id = driver.runScan(API_KEY, channel_id, file_contents, "output_dir_zip.zip")[0]
print "Scan ID        -> #{scan_id}\n"

waf_id  = driver.createWaf(API_KEY, WAF_TYPE, WAF_NAME)[0]
print "Waf ID         -> #{waf_id}\n"
print driver.addWaf(API_KEY, waf_id, app_id).to_s + "\n"

#-----------------------------------------------------------------------------
#                    View Open Vulnerabilities In Threadfix
#-----------------------------------------------------------------------------
if TF_DEMO
	pause "About to view open vulnerabilities in Threadfix.\n" if BREAKS
	
	if !ATTACK_DEMO
		browser.show 
	end
	browser.go_to_url 'http://localhost:8080/threadfix/'
	while browser.not_logged_in?
		browser.login 
		sleep(1)
	end
	browser.go_to_threadfix_app ORG_ID, app_id
end

#-----------------------------------------------------------------------------
#                     Pull Rules, Update Rules, Restart WAF
#-----------------------------------------------------------------------------
pause "About to pull rules and update the WAF.\n" if BREAKS

waf_rules = driver.pullWafRules(API_KEY, waf_id, WAF_DIRECTIVE)[0]
print "Rules = " + waf_rules + "\n"

if waf_rules.class.to_s != "String"
	print "No rules were generated!"
	Process.exit
end

print "Uploading WAF rules using SCP Library.\n"
waf.update_rules_file waf_rules

print "Restarting #{WAF_TYPE}\n"
waf.restart

#-----------------------------------------------------------------------------
#                              Second Attack Demo
#-----------------------------------------------------------------------------
if ATTACK_DEMO
	pause "About to conduct second attack demo.\n" if BREAKS

	print "Conducting second attack demo.\n"
	browser.use_normally waf.get_target_url
	browser.attack waf.get_target_url
end

#-----------------------------------------------------------------------------
#                          Re-run Scan & Upload Log File
#-----------------------------------------------------------------------------
pause "About to run second #{scanner_name} scan and upload scan and WAF log.\n" if BREAKS

print "Running second #{scanner_name} scan.\n"
new_scan_contents = scanner.scan 'output_dir3', URL, TARGET_APP

waf.upload_log driver, waf_id

scan_id = driver.runScan(API_KEY, channel_id, new_scan_contents, "output_dir_zip2.zip")[0]
print "New Scan ID -> #{scan_id}\n"

#-----------------------------------------------------------------------------
#               View (Hopefully) Closed Vulnerabilities In Threadfix
#-----------------------------------------------------------------------------
if TF_DEMO
	pause "About to view vulnerabilities again in Threadfix.\n" if BREAKS
	browser.go_to_threadfix_app_closed_vulns ORG_ID, app_id
end

#-----------------------------------------------------------------------------
#                             Conclusion, cleanup
#-----------------------------------------------------------------------------
#print "Total time taken = #{Time.now - start_time}\n\n"

if (ATTACK_DEMO || TF_DEMO)
	if TF_DEMO
		pause "About to log out of Threadfix and close the browser.\n"
		browser.logout
	end
	browser.exit
end
