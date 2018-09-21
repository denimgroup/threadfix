README.txt

There are a few components in this util folder.

1. Threadfix Vulnerability Demo Site

This is a collection of pages that showcases a number of vulnerabilities that we can automatically defend against.
To use, drop the folder into your Apache directory and set up configuration from there. 
It requires PHP with LDAP turned on and Directory Indexing also turned on in order for that page to work.
It was developed on Apache 2.2 with PHP 5 on Windows 7, all other configurations are untested.

2. Scripts

These are the Ruby scripts that I use for convenience through automation.
They can perform a range of tasks, including:

	1. Uploading scans from any folder automatically through RPC calls (upload_scans.rb)
	2. Generating appropriate generic SQL mappings for channel vulns and severities (map_generator.rb)
	3. Constructing Netsparker scans with arbitrary combinations of current vulnerabilities (reports.rb)
	4. Running w3af and skipfish scans with a good degree of flexibility (w3af_driver.rb, skipfish_driver.rb)
	5. Automate IE to run through a vuln demo and go to arbitrary addresses (ie_driver.rb)
	6. Scanning, uploading scans, downloading WAF rules, uploading WAF rules to the server, 
		re-scanning, and re-uploading to verify vulnerabilities have been closed (shc.rb, tf_demo_site.rb)
	7. Listen in on a directory for changes and prompting a process like item 6 (file_listener.rb)
	8. Interface with WAFs to upload new rules, download logs,
		and reset configurations (snort_driver.rb, mod_security_driver.rb, update_sensor_config.rb)
	
All of them run in a Windows environment, although to use some features such as skipfish, 
	you must install Cygwin. Cygwin must have Ruby installed.
The one click installer for Windows can be found at http://www.ruby-lang.org/en/downloads/

Environments other than Windows 7 are untested but a lot of the code should still work. 
The Win32OLE ones and the file listener script will not because they depend on Windows.
