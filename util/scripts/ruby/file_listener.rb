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
# file_listener.rb

=begin
Dependencies:
	SSH library
	Win32 File monkeypatching
	MD5 hashing

Usage:
	This script functions in one of two similar ways (and probably could be reduced to a much simpler form).
	This works great on local directories, but remote ones need to be accessible by mounting or SSH.
	Mounted directories just take the Windows filepath as an argument.
	SSH directories can be specified with the -ip, -pw, and -user flags on the command line.
	
	Once it's correctly configured, the script will run scans automatically, run scans with a prompt,
	or not run scans at all.

	It can also be configured to log output into a file with the -log option.
	
=end

require 'rubygems'
require 'net/ssh'
require 'win32/file'
require 'digest/md5'

if ARGV.size == 0
	print 'The first argument must be the folder location.
The others can be any of 
-log -output=log
-print -output=print
-auto -auto-scan
-noscan
-ip   (the address  for SSH)
-pw   (the password for SSH)
-user (the username for SSH)
'
	Process.exit
end

def parse_args
	flags = {}
	hash_next_value = false
	prev = nil
	ARGV.each do |arg|
		if arg[0].chr == "-"
			if ["-ip", "-pw", "-user"].include? arg
				hash_next_value = true
				prev = arg
			else
				flags[arg.downcase] = true
			end
		elsif hash_next_value
			flags[prev.downcase] = arg
			hash_next_value = false
			prev = nil
		end
	end
	return flags
end

flags = parse_args
flags.default = false

LOG   = (flags["-output=log"] || flags["-log"])
PRINT = (flags["-output=print"] || flags["-print"] || (!LOG))
AUTO  = (flags["-auto-scan"] || flags["-auto"])
SCAN  = !flags["-noscan"]
HTTPD = flags["-httpd"] || flags["-watch-httpd.conf"] || flags["-httpd.conf"]

SSH_IP   = flags["-ip"] || "192.168.1.20"
SSH_PW   = flags["-pw"] || flags["password"] || "password"
SSH_USER = flags["-user"] || flags["username"] || "mac"

def log line
	if LOG
		file = File.new("listener.log", "a")
		file << line
		file.close
	end
	if PRINT
		print line
	end
end

def scan
	`ruby tf_demo_site.rb -config default.conf`
end

def get_ssh_entries ssh, dir_name
	ssh.exec!("echo \"#{SSH_PW}\" | sudo -S ls #{dir_name}")
end

def get_ssh_contents ssh, entry_path
	ssh.exec!("echo \"#{SSH_PW}\" | sudo -S cat #{entry_path}")
end

def read_ssh_directory ssh, dir_root, extension, hash, total	
	directories = []
		
	get_ssh_entries(ssh, dir_root + extension).each do |entry|
		full_name = dir_root + extension + entry.strip
		#print "full name is #{full_name}\n"
						
		if entry == "." || entry == ".." || entry[0..4] == "[sudo]"
			next
		end
		
		if is_ssh_dir? ssh, full_name
			directories << entry.strip
			next
		end
		
		digest = Digest::MD5.hexdigest(get_ssh_contents(ssh, full_name))
		
		hash[extension + entry.strip] = digest
		total << digest
	end
	
	directories.each do |directory|
		read_ssh_directory ssh, dir_root, extension + directory + "/", hash, total
	end
	
	return hash, total
end

def is_ssh_dir? ssh, name
	name = ssh.exec!("sudo file #{name}")
	name.include? "directory"
end

def watch_ssh_directory directory
	if directory[-1] != '/'
		directory = directory + '/'
	end
	
	log "Opening SSH Session.\n"
	
	Net::SSH.start(SSH_IP, SSH_USER, :password => SSH_PW) do |ssh| 
		last_digest = ""
		last_hash   = {}

		first_time = true

		edited = false
		httpd_edited = false

		log "Opened. Starting main loop.\n"

		while true
			hash, total_digest = read_ssh_directory ssh, directory, "", {}, ""
			
			if last_digest != total_digest && !first_time		
				hash.each do |key, value|
					if last_hash[key] == nil
						log "File #{key} was added.\n"
						edited = true
					elsif last_hash[key] != value
						if HTTPD
							if key.include? "httpd.conf"
								log "File #{key} was edited.\n"
								edited = true
								httpd_edited = true 
							end
						else
							log "File #{key} was edited.\n"
							edited = true
						end
					end
				end
				
				last_hash.each do |key, value|
					log "File #{key} was deleted.\n" if hash[key] == nil
					edited = true
				end
				
				last_digest = total_digest
				last_hash   = hash
			end
			
			if (SCAN && edited && (!HTTPD || httpd_edited))
				if AUTO
					log "Starting automatic scan.\n"
					scan
					log "Finished automatic scan.\n"
				elsif PRINT
					print "Do you wish to scan the target? (y/n) "
					answer = STDIN.gets
					if answer.strip == "y"
						log "Starting Scan.\n"
						scan
						log "Finished Scan.\n"
					end
				end
				log "Resuming listening.\n"
				edited = false
			end
			
			last_digest = total_digest if first_time
			last_hash   = hash if first_time
			first_time  = false
			
			sleep(3)
		end
	end
end

def get_dir_entries dir_name
	Dir.entries(dir_name)
end

def get_file_contents entry_path
	File.read entry_path
end

def read_file_directory dir_root, extension, hash, total	
		directories = []
			
		get_dir_entries(dir_root + extension).each do |entry|
			full_name = dir_root + extension + entry
				
			if entry == "." || entry == ".." 
				next
			end
			if File.directory? full_name
				directories << entry
				next
			end
			
			digest = Digest::MD5.hexdigest(get_file_contents(full_name))
			
			hash[extension + entry] = digest
			total << digest
		end
		
		directories.each do |directory|
			read_file_directory dir_root, extension + directory + "\\", hash, total
		end
		
		return hash, total
	end

def watch_file_directory directory
		if directory[-1] != '\\'
			directory = directory + '\\'
		end

		last_digest = ""
		last_hash   = {}

		first_time = true

		edited = false
		httpd_edited = false
		
		log "Initializing File listening.\n"

		while true
			hash, total_digest = read_file_directory dir_name, "", {}, ""
			
			if last_digest != total_digest && !first_time		
				hash.each do |key, value|
					if last_hash[key] == nil
						log "File #{key} was added.\n"
						edited = true
					elsif last_hash[key] != value
						if HTTPD
							if key.include? "httpd.conf"
								log "File #{key} was edited.\n"
								edited = true
								httpd_edited = true 
							end
						else
							log "File #{key} was edited.\n"
							edited = true
						end
					end
				end
				
				last_hash.each do |key, value|
					log "File #{key} was deleted.\n" if hash[key] == nil
					edited = true
				end
				
				last_digest = total_digest
				last_hash   = hash
			end
			
			if (SCAN && edited && (!HTTPD || httpd_edited))
				if AUTO
					log "Starting automatic scan.\n"
					scan
					log "Finished automatic scan.\nResuming Listening.\n"
				else
					print "Do you wish to scan the target? (y/n) " if PRINT
					answer = STDIN.gets
					if answer.strip == "y"
						log "Starting Scan.\n"
						scan
					end
					log "Resuming listening.\n"
					edited = false
				end
			end
			
			last_digest = total_digest if first_time
			last_hash   = hash if first_time
			first_time  = false
			
			sleep(3)
		end
	end

dir_name = ARGV[0]

if dir_name[0..2] == "ssh"
	dir_name = dir_name.gsub(/^ssh:/, '')
	watch_ssh_directory dir_name
else
	watch_file_directory dir_name
end

