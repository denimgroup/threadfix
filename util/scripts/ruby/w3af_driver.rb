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
# W3afDriver.rb

=begin
Dependencies:
	Make sure the calls to require work.

Usage:
	scan() works just like in skipfish_driver.rb. Here we actually rewrite the script
	and pass that in as an argument rather than trying to feed w3af a bunch of instructions
	through a pipe.
	
=end

require 'rubygems'
require 'net/ssh'
require 'net/scp'
require 'base64'

class W3afDriver
	def scan output_name, base_url, target_app = "peruggia"
		w3af_command = "w3af_console.bat -s scripts/threadfix.w3af -n"
		script = generate_script output_name, base_url, target_app
		File.open("C:/cygwin/scanners/w3af/w3af/scripts/threadfix.w3af", 'w') { |f| f.write(script) }
		
		output_file_name = "C:/cygwin/scanners/w3af/w3af/output-w3af.xml"
		
		rewrite_w3af_unicode_file true
		`#{w3af_command}`
		rewrite_w3af_unicode_file false
		
		file_contents = nil
		file_contents = File.new(output_file_name, "rb+").read if File.exist? output_file_name
		print "SOMETHING WENT WRONG IN GRABBING THE W3AF FILE\n" if (file_contents.nil? || file_contents.strip == "")
		return Base64.encode64(file_contents).gsub("\n", '')
	end
	
	def generate_script output_name, base_url, target_app
		return "plugins\n" +
			"output console,textFile,xmlFile\n" +
			"output config textFile\n" +
			"	set fileName output-w3af.txt\n" +
			"	set verbose True\n" +
			"	back\n" +
			"output config xmlFile\n" +
			"	set fileName output-w3af.xml\n" +
			"	set verbose True\n" +
			"	back\n" +
			"output config console\n" +
			"	set verbose False\n" +
			"	back\n" +
			"audit osCommanding eval formatString LDAPi xss sqli blindSqli xsrf responseSplitting xpath\n" +
			"discovery urlFuzzer detectReverseProxy detectTransparentProxy findBackdoor fingerprint_WAF\n" +
			"discovery webSpider\n" +
			"	discovery config webSpider\n" +
			"		set onlyForward True\n" +
			"	back\n" +
			"back\n" +
			"target\n" +
			"	set target http://#{base_url}/#{target_app}/\n" +
			"back\n" +
			"http-settings\n" +
			"	set maxRetrys 0\n" +
			"	set timeout 3\n" +
			"back\n" +
			"start\n" +
			"exit"
	end
	
	def rewrite_w3af_unicode_file comments
		lines = IO.readlines('C:\cygwin\scanners\w3af\python26\Lib\site-packages\pyreadline\unicode_helper.py');
			
		file  = File.open('C:\cygwin\scanners\w3af\python26\Lib\site-packages\pyreadline\unicode_helper.py', 'w');
		
		line1, line2, newline1, newline2 = "", "", "", ""
		
		if comments
			line1    = 'if isinstance(text, str):'
			line2    = 'return text.decode(pyreadline_codepage, "replace")'
			newline1 = "#    if isinstance(text, str):\n"
			newline2 = "#        return text.decode(pyreadline_codepage, \"replace\")\n"
		else
			line1    = '#    if isinstance(text, str):'
			line2    = '#        return text.decode(pyreadline_codepage, "replace")'
			newline1 = "    if isinstance(text, str):\n"
			newline2 = "        return text.decode(pyreadline_codepage, \"replace\")\n"
		end
		
		lines.each do |line|
			if line.strip == line1
				file << newline1
			elsif line.strip == line2	
				file << newline2
			else
				file << line
			end
		end
		
		file.close
	end
end

#W3afDriver.new.scan "output-w3af.txt", "192.168.1.40", "peruggia"