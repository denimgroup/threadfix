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
# skipfish_driver.rb
# This file holds the SkipfishDriver class.

=begin
Dependencies:
	1. Any gems.
	2. Needs to be in the same directory as Cygwin.bat for the current pipe to work.
	3. There must be the file skipfish_do_scan.rb in the same directory
	      so that it can be executed in the Cygwin environment.
	4. Cygwin must have Ruby installed also.

Usage:
	It follows the same informal interface as the w3af driver.
	scan(), given an output name, url, and target app, will scan your target.
	Everything else is in support of scan().
=end

require 'net/ssh'
require 'net/scp'
require 'base64'
require 'zip/zip'
require 'find'
require 'fileutils'
include FileUtils

class SkipfishDriver
	def scan output_name, base_url, target_application = "peruggia"
		# Moves aside the needed directories for the scan to run and runs it.
		ensure_file_is_available(directory + "/" + output_name)
	
		run_skipfish_scan(output_name, base_url, target_application)
	
		ensure_file_is_available "#{directory}/#{output_name}_zip.zip"
	
		print "Zipping output folder.\n"
		
		root = "#{directory}"
		new_zip_file = "#{directory}/#{output_name}_zip.zip"

		Zip::ZipFile.open(new_zip_file, Zip::ZipFile::CREATE) do |zipfile|
			Find.find(root) do |path|
				dest = /#{output_name}\/(\w.*)/.match(path)
				zipfile.add(output_name + "/" + dest[1], path) if dest
			end
		end
		
		if File.exist? new_zip_file
			print "Got the zip file.\n" 
		else
			print "FATAL ERROR TRYING TO GRAB ZIP FILE.\n"
		end
		file_contents = base64_encode_file_contents(new_zip_file)
		return file_contents
	end
	
	private
	
	def directory
		"C:/cygwin/scanners/skipfish-1.92b"
	end

	def run_skipfish_scan output_dir, base_url, target_application
		skipfish_command = "./skipfish -m 30  -Y -LV -W dictionaries/minimal.wl -q 0x0f691ff7 -e -o " + output_dir +
						" -b ie -I http://#{base_url}/#{target_application} http://#{base_url}/#{target_application}/index.php"

		IO.popen("Cygwin.bat", mode="w+") do |pipe|
			pipe.puts "cd /; ruby skipfish_do_scan.rb \"#{skipfish_command}\""
			pipe.flush; pipe.close;
		end
	end

	def ensure_file_is_available file_name
		File.rename file_name, file_name + Time.now.to_s.gsub(" ", "").gsub(":","").gsub("-","") if File.exist?(file_name)
	end

	def base64_encode_file_contents file_name
		Base64.encode64(File.new(file_name, "rb+").read).gsub("\n", '')
	end
end