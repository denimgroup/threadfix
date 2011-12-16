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
# snort_driver.rb

=begin
Dependencies:
	1. Any gems.

Usage:
	It follows the same informal interface as the mod_security driver.
	update_server_configuration(), restart(), update_rules_file(), and upload_log()
	all do what you would expect.
	
=end

require 'net/ssh'
require 'net/scp'
require 'base64'

class SnortDriver
	attr_accessor :sensor_username, :sensor_password, :sensor_ip
	
	def initialize senser_username, sensor_password, sensor_ip, crs_enabled = false
		self.sensor_username, self.sensor_password, self.sensor_ip = 
			 senser_username, sensor_password, sensor_ip
	end

	def get_target_url
		'192.168.1.40'
	end
	
	def update_server_configuration
		commands = [ "echo \"password\" | sudo -S brctl delif br0 eth1",
					"sudo iptables -D FORWARD 1",
					"sudo iptables -I FORWARD -j QUEUE",
					"sudo apache2ctl stop",
					"sudo kill $(pidof snort)",
					"sudo /usr/local/snort/bin/snort -Q -D --daq afpacket -u snort -g snort -c " +
					"/usr/local/snort/etc/snort.conf -i eth0:eth1" ]
					
		Net::SSH.start(self.sensor_ip, self.sensor_username, :password => self.sensor_password) do |ssh|
			to_print = ""
			commands.each { |command| to_print << ssh.exec!(command).to_s }
			#print to_print
		end
	end

	def restart
			Net::SSH.start(self.sensor_ip, self.sensor_username, :password => self.sensor_password) do |ssh|
			ssh.exec! "echo \"\" > /var/log/snort/alert.csv"
		
			snort_pid = (ssh.exec!("pidof snort"))
			print "Snort's pid = #{snort_pid.strip}\n" if !snort_pid.nil?

			print "Killing Snort process.\n"
			ssh.exec! "echo \"password\" | sudo -S /bin/kill -HUP $(/bin/pidof snort)"
			print "Waiting for Snort to die.\n"
			
			# Wait for Snort to die
			snort_pid = (ssh.exec!("pidof snort"))
			while !snort_pid.nil? 
				sleep 1
				snort_pid = ssh.exec!("pidof snort")
			end
			
			print "Starting Snort again.\n"
			snort_command = "echo \"password\" | sudo -S /usr/local/snort/bin/snort -D -Q " + 
				"--daq afpacket -u snort -g snort -c /usr/local/snort/etc/snort.conf -i eth0:eth1"
			
			ssh.exec! snort_command
			
			# Wait for Snort to come up
			snort_pid = (ssh.exec!("pidof snort"))
			while snort_pid.nil? 
				sleep 1 
				snort_pid = ssh.exec!("pidof snort")
			end
			
			print "Snort's pid = #{snort_pid.strip}\n"
		end
	end
	
	def update_rules_file new_content
		Net::SCP.start(self.sensor_ip, self.sensor_username, :password => self.sensor_password) do |scp|
			scp.upload! StringIO.new(new_content), "/usr/local/snort/rules/threadfix.rules"
		end
	end
	
	def upload_log driver, api_key, waf_id
		print "Uploading Logs\n"
		log_contents = ""
		Net::SSH.start(self.sensor_ip, self.sensor_username, :password => self.sensor_password) do |ssh| 
			log_contents = ssh.exec!("cat /var/log/snort/alert.csv")
		end

		result = driver.uploadWafLog(api_key, waf_id, log_contents)[0]
		print "Our rules were fired #{result} times.\n"

		result = driver.pullWafRuleStatistics(api_key, waf_id)[0];
		hash   = eval("{#{result}}")

		hash.keys.sort.each do |key|
			print "Rule with pid of #{key} was fired #{hash[key]} times.\n"
		end
	end
end
