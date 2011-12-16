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
# update_sensor_config.rb

=begin
Dependencies:
	Make sure the calls to require work.

Usage:
	This script lets you set WAF configurations with any sets of WAF rules currently in threadfix.
	For example, to update from any configuration to mod_security with deny rules from a WAF with id 11, do
	ruby update_sensor_config.rb -type mod_security -waf 11 -directive deny
	
=end

require 'rubygems'
require 'soap/wsdlDriver'
require 'net/ssh'
require 'net/scp'
require 'skipfish_driver.rb'
require 'snort_driver.rb'
require 'mod_security_driver.rb'
require 'w3af_driver.rb'

def exit
	print "Usage: ruby update_sensor_config.rb -type waf_type [-waf waf_id -directive directive]"
	Process.exit
end

def get_driver
	wsdl_url = 'http://localhost:8080/services/RPCService?WSDL'
	return SOAP::WSDLDriverFactory.new(wsdl_url).create_rpc_driver
end

SNORT = "Snort"
MOD_SEC = "mod_security"
USERNAME  = "mac"
PASSWORD  = "password"

arg_hash = eval("{\"#{ARGV.join("\",\"")}\"}")

exit if arg_hash["-type"].nil?

waf_name = arg_hash["-type"]


if waf_name.downcase == SNORT.downcase
	WAF_TYPE = SNORT
	waf = SnortDriver.new "mac", "password", "192.168.1.20"
elsif waf_name.downcase == MOD_SEC.downcase
	WAF_TYPE = MOD_SEC
	waf = ModSecurityDriver.new "mac", "password", "192.168.1.20"
else
	exit
end

if arg_hash["-waf"].nil? || arg_hash["-directive"].nil? || arg_hash["-api"].nil?
	print "Clearing rule set and restarting.\n"
	waf.update_server_configuration
	waf.update_rules_file ""
	waf.restart
	Process.exit
end

waf_id = arg_hash["-waf"]
waf_directive = arg_hash["-directive"]
api_key = arg_hash["-api"]

waf.update_server_configuration

driver = get_driver

waf_rules = driver.pullWafRules(api_key, waf_id, waf_directive)[0]
print "Rules:\n" + waf_rules + "\n"

waf.update_rules_file waf_rules

print "updated!\n"

print "Restarting #{WAF_TYPE}\n"
waf.restart

