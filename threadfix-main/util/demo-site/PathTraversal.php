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
PathTraversal.php
This page lists places where you can access directories.

-->

<?php 
if (array_key_exists('action', $_GET))
{
	$myFile = str_replace("<", "&lt;", $_GET['action']);
	$myFile = str_replace(">", "&gt;", $myFile);
	
	if (($myFile == "PathTraversal.php") or ($myFile == ""))
	{
		echo "<html>
				<head>
					<title>Path Traversal</title>
				</head>
				<body>
				<h2> Path Traversal </h2>

				<ul>
					<li>You can access arbitrary file contents with the action parameter.</li>
				</ul>
				</body>
			</html>";
	} else {
		$fh = fopen($myFile, 'r');
		$theData = fread($fh, filesize($myFile));
		fclose($fh);
		echo $theData;
	}
} else {
	echo "<html>
			<head>
				<title>Path Traversal</title>
			</head>
			<body>
			<h2> Path Traversal </h2>

			<ul>
				<li>You can access arbitrary file contents with the action parameter. (/)</li>
			</ul>
			</body>
		</html>";

}
?>