<?php
////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
?>
<!-- LDAP Injection 2  -->
<!-- This page realizes an LDAP Injection vulnerability. 
In order to set this up, you need an appropriate server that recognizes LDAP at localhost on port 10389.
Just make sure it complies with the below code (or modify it if you want).
-->

<html>
	<head>
		<title>LDAP Injection2</title>
	</head>
	<body>
	
	<?php
		
	$ldaphost = "localhost";
	$ldapport = 10389;
	
	$ldapconn = ldap_connect($ldaphost, $ldapport) or die("Could not connect to ldaphost");
	
	if (!$ldapconn) {
		echo "BROKE AT CONNECTION<br/>";
	}
	
	if ($ldapconn) {
		$search_result=ldap_search($ldapconn, "ou=engineering,dc=fiveruns,dc=com", "(uid=" . $_POST['username'] . ")");
		
		if ($search_result) {
			$info = ldap_get_entries($ldapconn, $search_result);
			
			if ($info["count"] >= 1) {
				echo "Congratulations, you have logged in as " . $info[0]["cn"][0] . "!<br />";
			} else {
				echo "Login failed.<br>";
			}

			ldap_close($ldapconn);
		}
	}
	
	?>

	</body>
</html>
