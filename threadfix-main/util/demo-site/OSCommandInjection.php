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
<!-- OS Command Injection  -->
<!-- This page demonstrates an OS Command Injection vulnerability. -->
<html>
	<head>
		<title>OS Command Injection</title>
	</head>
	<body>
	<h2> OS Command Injection </h2>
	This is a submission page created to be vulnerable to OS Command Injection.<br/>
	The input is prefaced by the Windows type command. You can view file contents.<br/>
	I edited w3af to find a real vulnerability instead of an informational finding here.<br/>
	
	<form action="OSCommandInjection2.php" method="post">
		File: <input type="text" name="fileName" /><br/>
		<input type="submit" />
	</form>
	</body>
</html>
