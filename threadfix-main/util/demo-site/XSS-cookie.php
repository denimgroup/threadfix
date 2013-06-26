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
C
Injecting a newline into a cookie allows you to return any http response you want.
This page exhibits this vulnerability.

value2;%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20302%20Moved%20Temporarily%0d%0aContent-Type:%20text/html%0d%0aContent-Length%2026%0d%0a%0d%0a<html><h2>DONE</h2></html>
302%20Moved%20Temporarily
-->

<?php

if (array_key_exists('cookie', $_POST))
{
	header("Set-Cookie: vuln=" . $_POST['cookie']);
	header("Location: /demo/XSS-cookie.php");
}

?>

<html>
	<head>
		<title>XSS - cookie</title>
	</head>
	<body>
		<h2> XSS - cookie </h2>
		The cookie's value is <?php if (array_key_exists('vuln', $_COOKIE)) { echo $_COOKIE["vuln"]; }?>
		<form action="XSS-cookie.php" method="post">
			New Cookie value: <input type="text" name="cookie" />
			<input type="submit" />
		</form>
	</body>
</html>
