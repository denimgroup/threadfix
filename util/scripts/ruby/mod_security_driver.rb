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
#mod_security_driver.rb

=begin
Dependencies:
	SSH Library
	Base64 Library

Usage:
	This class includes methods to 
		1. reroute the mod_security proxy
		2. upload rules
		3. restart the WAF
		4. update configuration
		5. upload the log file to Threadfix
	
=end


require 'net/ssh'
require 'net/scp'
require 'base64'

class ModSecurityDriver
	attr_accessor :sensor_username, :sensor_password, :sensor_ip, :core_rules_active
	attr_accessor :log_location
	attr_accessor :rules_location
	attr_accessor :core_rules_line
	
	def initialize senser_username, sensor_password, sensor_ip, core_rules_active=false
		self.sensor_username, self.sensor_password, self.sensor_ip, self.core_rules_active = 
			 senser_username, sensor_password, sensor_ip, core_rules_active
			 
		self.log_location    = "/var/log/apache2/error.log"
		self.rules_location  = "/etc/apache2/crs_rules/threadfix.conf"
		self.core_rules_line = "Include crs_rules/base_rules/*.conf\n"
	end
	
	def get_target_url
		'192.168.1.20'
	end
	
	def reroute_proxy address
		contents = "LoadModule proxy_http_module /usr/lib/apache2/modules/mod_proxy_http.so

ProxyRequests On
ProxyVia On

<Proxy *>
	Order allow,deny
	Allow from all
</Proxy>

ProxyPass / http://#{address}/
ProxyPassReverse / http://#{address}/

Include crs_rules/*.conf "

		Net::SSH.start(self.sensor_ip, self.sensor_username, :password => self.sensor_password) do |ssh|
			p ssh.exec!("echo \"password\" | sudo -S echo \"#{contents}\" > ~/temp.conf")
			p ssh.exec!("sudo mv ~/temp.conf /etc/apache2/httpd.conf")
		end
	end

	def update_server_configuration
		commands = [ "echo \"#{self.sensor_password}\" | sudo -S brctl addif br0 eth1", 
					"sudo iptables -D FORWARD 1",
					"sudo iptables -I FORWARD -j ACCEPT",
					"sudo kill $(pidof snort)",
					"echo \"\" > temp.txt",
					"sudo cp temp.txt #{self.log_location}",
					"sudo apache2ctl start",
					"sudo apache2ctl restart"]
		Net::SSH.start(self.sensor_ip, self.sensor_username, :password => self.sensor_password) do |ssh|
			to_print = ""
			commands.each { |command| to_print << ssh.exec!(command).to_s }
			#print to_print
		end
	end
	
	def restart
		Net::SSH.start(self.sensor_ip, self.sensor_username, :password => self.sensor_password) do |ssh|
			ssh.exec! "echo \"password\" | sudo -S apache2ctl restart"
			ssh.exec! "sudo echo \"\" > #{self.log_location}"
		end
	end

	def update_rules_file new_content
		Net::SCP.start(self.sensor_ip, self.sensor_username, :password => self.sensor_password) do |scp|
			if self.core_rules_active
				new_content = self.core_rules_line + new_content
			end
			scp.upload! StringIO.new(new_content), self.rules_location
		end
	end
	
	def upload_log driver, api_key, waf_id
		print "Uploading Logs\n"
		log_contents = ""
		Net::SSH.start(self.sensor_ip, self.sensor_username, :password => self.sensor_password) do |ssh| 
			log_contents = ssh.exec!("cat #{self.log_location}")
		end
		
		result = driver.uploadWafLog(api_key, waf_id, log_contents)[0]
		print "Our rules were fired #{result} times.\n"

		result = driver.pullWafRuleStatistics(api_key, waf_id)[0];

		hash   = eval("{#{result}}")

		hash.keys.sort.each do |key|
			print "Rule with id of #{key} was fired #{hash[key]} times.\n"
		end
	end
end

=begin httpd.conf - find at /etc/apache2/httpd.conf
"LoadModule proxy_http_module /usr/lib/apache2/modules/mod_proxy_http.so

ProxyRequests On
ProxyVia On

<Proxy *>
	Order allow,deny
	Allow from all
</Proxy>

ProxyPass / http://192.168.1.30:8080/
ProxyPassReverse / http://192.168.1.30:8080/

Include crs_rules/*.conf "

=end
	