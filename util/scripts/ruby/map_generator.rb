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
# map_generator.rb
# Written by mcollins

# Dependencies: import.sql needs to be in the same directory so that it can be scraped.

# Usage: To generate vuln mappings, set up a hash mapping codes to generic IDs.
#        A sample is below.
#        To generate severity mappings, use a similar hash with codes to the SQL macros.
#        Those are listed here for convenience.

#        Be sure to change the CHANNEL field to the correct value.

#        The outputs can be seen in files named vulnerability_maps.sql and severity_maps.sql

CHANNEL = '@netsparker_net_channel_id'

=begin generic severities

SET @generic_severity_critical_id := (SELECT id FROM GenericSeverity WHERE name = 'Critical');
SET @generic_severity_high_id := (SELECT id FROM GenericSeverity WHERE name = 'High');
SET @generic_severity_medium_id := (SELECT id FROM GenericSeverity WHERE name = 'Medium');
SET @generic_severity_low_id := (SELECT id FROM GenericSeverity WHERE name = 'Low');
SET @generic_severity_info_id := (SELECT id FROM GenericSeverity WHERE name = 'Info');

vuln_maps = { 
	'Permanent cross site scripting vulnerability' => '79',
	'SQL injection vulnerability'   => '89',
	'Potentially Interesting File'  => '425',
	'LDAP injection vulnerability'  => '90',
	'Format string vulnerability'   => '134',
	'OS commanding vulnerability'   => '78',
	'XPATH injection vulnerability' => '643',
	'eval() input injection vulnerability' => '95',
	'Blind SQL injection vulnerability'    => '89',
	'Cross site scripting vulnerability'   => '79'
	}
		
severity_maps = { 'Critical' => '@generic_severity_critical_id',
				  'Important' => '@generic_severity_high_id',
				  'Medium' => '@generic_severity_medium_id',
				  'Low' => '@generic_severity_low_id',
				  'Information' => '@generic_severity_info_id'
				  }
				  
=end

vuln_maps = { 
	'Cross-site scripting (reflected)' => '79',
	'SQL injection'   => '89',
	'OS command injection' => '78',
	'Directory listing' => '548',
	'Private IP addresses disclosed' => '212',
	'HTML does not specify charset' => '173'
	}

severity_maps = { 'Critical' => '@generic_severity_critical_id',
				  'Important' => '@generic_severity_high_id',
				  'Medium' => '@generic_severity_medium_id',
				  'Low' => '@generic_severity_low_id',
				  'Information' => '@generic_severity_info_id'
				  }

{'Medium' => '@generic_severity_medium_id',
				  'High' => '@generic_severity_high_id',
				  'Information' =>'@generic_severity_info_id' }

def get_severity key
	{ 'Critical' => '@generic_severity_critical_id',
	  'Medium' => '@generic_severity_medium_id',
	  'High' => '@generic_severity_high_id',
	  'Low' => '@generic_severity_low_id',
	  'Info' =>'@generic_severity_info_id' }[key]
end
	
def gen_vuln_maps channel, hash
	ids, macros = {}, {}

	IO.readlines("import.sql").each do |line|
		if line =~ /SET ([^:]+) := \(SELECT id FROM GenericVulnerability WHERE name = '([^.]+)'\);/
			macros[$2] = $1.strip
		elsif line =~ /INSERT INTO GenericVulnerability \(name, id\) VALUES \('(.+)', '([^']+)'\);/
			ids[$2] = $1
		end
	end

	#print macros[ids['548']]

	file = File.new('vulnerability_maps.sql', 'w+')
	
	hash.each { |code, id| file << "INSERT INTO ChannelVulnerability (name, code, channelTypeId) VALUES ('#{code}', '#{code}', #{channel});\n" } 

	hash.each do |code, id|
		file << "INSERT INTO VulnerabilityMap (mappable, ChannelVulnerabilityId, GenericVulnerabilityId) VALUES (1, \n" +
			"\t(SELECT id FROM ChannelVulnerability WHERE ChannelTypeId = #{channel} AND code = #{code.inspect}), #{macros[ids[id]]});\n"
	end
end

def gen_severity_maps channel, hash
	ids, macros = {}, {}

	file = File.new('severity_maps.sql', 'w+')
								   
	hash.each { |code, id| file << "INSERT INTO ChannelSeverity (name, code, channelTypeId) VALUES ('#{code}', '#{code}', #{channel});\n" } 

	hash.each do |code, id|
		file << "INSERT INTO SeverityMap (ChannelSeverityId, GenericSeverityId) VALUES (\n" +
				"\t(SELECT id FROM ChannelSeverity WHERE ChannelTypeId = #{channel} AND code = '#{code}'), #{id});\n"
	end
end

gen_vuln_maps CHANNEL, vuln_maps

gen_severity_maps CHANNEL, severity_maps