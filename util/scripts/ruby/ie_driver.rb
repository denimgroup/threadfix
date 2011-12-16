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
#ie_driver.rb
=begin
Dependencies:
	win32ole

Usage:
	This class provides a wrapper around a Win32OLE object in a similar way to WATiR but more focused.
	It also starts a popup watcher as a separate thread.
	
=end

require 'win32ole'

def check_for_popups
    autoit = WIN32OLE.new('AutoItX3.Control')

    loop do
		ret = autoit.WinWait('Message from webpage', '', 1)
        
		if (ret==1)
			#autoit.ControlFocus("Message from webpage", "", "&Ok")
			#autoit.Send('{enter}')
			autoit.ControlClick("[Class:#32770]","","Ok")
			autoit.Send('{enter}')
		end
        
		sleep 1
    end
end

$popup  = Thread.new { check_for_popups }
at_exit { Thread.kill($popup) }

class IEDriver
	attr_accessor :browser
	
	def initialize
		self.browser = WIN32OLE.new('InternetExplorer.Application')
	end
	
	def show
		self.browser.Visible = true
	end
	
	def hide
		self.browser.Visible = false
	end
	
	def exit
		self.browser.Quit
	end
	
	def not_logged_in?
		ret = false
		if self.browser.LocationURL =~ /http:\/\/localhost:8080\/threadfix\/login\.jsp.*/
			ret = true
		end
		
		return ret
	end
	
	def login
		if not_logged_in?
			self.browser.Document.All.j_username.Value = "mac"
			self.browser.Document.All.j_password.Value = "password"
			input = nil
			self.browser.Document.All.each do |item|
				if (item.tagName == 'INPUT')
					input = item
				end
			end
			input.click
		end
		wait_for_ready
	end
	
	def logout
		self.browser.Document.all.each do |item|
			if item.tagName == 'A' && item.toString == "http://localhost:8080/threadfix/j_spring_security_logout"
				item.click
				wait_for_ready
				break
			end
		end
	end
	
	def wait_for_ready
		sleep(1) until self.browser.ReadyState == 4
	end
	
	def go_to_threadfix_app org_id, app_id
		go_to_url "http://localhost:8080/threadfix/organizations/#{org_id}/applications/#{app_id}"
		wait_for_ready
	end
	
	def go_to_threadfix_app_closed_vulns org_id, app_id
		go_to_url "http://localhost:8080/threadfix/organizations/#{org_id}/applications/#{app_id}/closedVulnerabilities"
		wait_for_ready
	end
	
	def go_to_url address
		self.browser.Navigate address
		wait_for_ready
	end
	
	def attack ip
		go_to_url 'http://' + ip + '/vicnum/'
		
		count = 0
		button = nil
		self.browser.Document.All.Tags('INPUT').each do |item|
			count += 1
			if count == 1
				sleep(0.5)
				item.Value = "<script>alert('XSS')</script>"
				sleep(0.5)
			end
			if count == 3
				button = item
				break
			end
		end
		button.click
		sleep(2)
	end
	
	def use_normally ip 
		go_to_url 'http://' + ip + '/vicnum/'
		
		count = 0
		button = nil
		self.browser.Document.All.Tags('INPUT').each do |item|
			count += 1
			if count == 1
				sleep(0.5)
				item.Value = "Threadfix"
				sleep(0.5)
			end
			if count == 3
				button = item
				break
			end
		end
		button.click
		sleep(2)
	end
	
	def go_fullscreen
		self.browser.FullScreen = true
	end
	
	def self.test 
		browser = IEDriver.new
		browser.show
		browser.go_to_url 'http://localhost:8080/threadfix/'
		browser.login
		sleep(3)
		browser.logout
		sleep(3)
		browser.exit
	end
	
	def self.test_normal 
		browser = IEDriver.new
		browser.show
		browser.use_normally
		sleep(0.5)
		browser.exit
	end
	
	def self.test_attack
		browser = IEDriver.new
		browser.show
		browser.attack
		sleep(0.5)
		browser.exit
	end
	
	def self.test_both
		browser = IEDriver.new
		browser.show
		browser.use_normally
		browser.attack
		sleep(0.5)
		browser.exit
	end
end

eval("IEDriver.#{ARGV[0]}") if ARGV[0..4] == 'test_'
