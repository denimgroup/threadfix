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
<!-- XPath Injection 2  -->
<!-- This page realizes an XPath Injection vulnerability. -->

<html>
	<head>
		<title>XPath Injection</title>
	</head>
	<body>
	
	<?php
	
	$doc = new DOMDocument;
	
	$doc->preserveWhiteSpace = false;
	$doc->Load('users.xml');
		
	$xpath = new DOMXPath($doc);

	$ids = $xpath->query("//user[name/text()='" . $_POST['username'] . "' and password/text()='" . $_POST['password'] . "']/id");
	
	$userId = 0;
	
	if ($ids == False)
	{
		echo 'Incompatible XPath key, either ' . $_POST['username'] . ' or ' . $_POST['password'];
	} else {
		foreach ($ids as $id)
		{
			$userId = $id->nodeValue;
			break;
		}
		
		if ($userId == 0)
		{
			echo 'The User was not found.';
		} else {
			$doc2 = new DOMDocument;
			
			$doc2->preserveWhiteSpace = false;
			$doc2->Load('users.xml');
			
			$xpath2 = new DOMXPath($doc2);

			$names = $xpath2->query("//user[id/text()='" . $userId . "']/name");
			
			foreach ($names as $name)
			{
				echo 'You have logged in as ' . $name->nodeValue . ' with id ' . $userId . '.';
				break;
			}
		}
	}
	
	?>

	</body>
</html>
