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
<!-- XPath Injection  -->
<!-- This page demonstrates an XPath Injection vulnerability. -->
<html>
	<head>
		<title>XPath Injection</title>
	</head>
	<body>
	<h2> XPath Injection </h2>
	This is a login created to be vulnerable to XPath Injection.<br/>
	This payload in the user field enables you to login with no security credentials.<br/>
	' or 1=1 or ''='
	
	<form action="XPathInjection2.php" method="post">
		Name: <input type="text" name="username" /><br/>
		Password: <input type="text" name="password" /><br/>
		<input type="submit" />
	</form>
	</body>
</html>
