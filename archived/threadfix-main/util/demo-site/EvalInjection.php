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
<!-- Eval Injection  -->
<!-- This page demonstrates an Eval Injection vulnerability. -->
<html>
	<head>
		<title>Eval Injection</title>
	</head>
	<body>
	<h2> Eval Injection </h2>
	This is a submission page created to be vulnerable to Eval Injection.<br/>
	<pre>One example payload is 
	thisbroke";sleep(5);"
which executes the sleep command.</pre>
	
	<form action="EvalInjection2.php" method="post">
		Command: <input type="text" name="command" /><br/>
		<input type="submit" />
	</form>
	</body>
</html>
