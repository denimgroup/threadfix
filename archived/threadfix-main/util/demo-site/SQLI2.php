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
<!--
SQL Injection test page
This page's intended use is to show unauthorized password retrieval using SQL Injection.
To get this working, you must have an appropriate MySQL configuration or tweak these settings.
-->

<html>
	<head>
		<title>SQL Injection Test</title>
	</head>
	<body>
	<h2> Search Result </h2>
		<?php
			//$db = new mysqli ("localhost", "root", "root", "threadfix");
			$query = "SELECT * FROM users where name = \"" . $_POST["username"] . "\";";
			
			$mysqli = new mysqli ("localhost", "root", "root", "threadfix");

			/* check connection */
			if (mysqli_connect_errno()) {
				printf("Connect failed: %s\n", mysqli_connect_error());
				exit();
			}

			/* execute multi query */
			if ($mysqli->multi_query($query)) {
				do {
					/* store first result set */
					if ($result = $mysqli->store_result()) {
						while ($row = $result->fetch_row()) {
							echo $row[0] . " - " . $row[1] . "<br/>";
						}
						$result->free();
					}

				} while ($mysqli->next_result());
			} else {
				printf("Error Message: %s\n", $mysqli->error);
			}

			/* close connection */
			$mysqli->close();
			
		?> 
	</body>
</html>
