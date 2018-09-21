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
This is the submission form.
-->

<html>
	<head>
		<title>SQL Injection Test</title>
	</head>
	<body>
	<h2> User Search </h2>
	Example payloads:
	<ul>
		<li>Jimmy"; SELECT id, password as name FROM users where name = "Jimmy</li>
		<li>John"; SELECT id, password as name FROM users where name = "John</li>
	</ul>
	<form action="SQLI2.php" method="post">
		Name: <input type="text" name="username" />
		<input type="submit" />
	</form>
	</body>
</html>
