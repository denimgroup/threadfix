:://////////////////////////////////////////////////////////////////////
::
::     Copyright (c) 2009-2013 Denim Group, Ltd.
::
::     The contents of this file are subject to the Mozilla Public License
::     Version 2.0 (the "License"); you may not use this file except in
::     compliance with the License. You may obtain a copy of the License at
::     http://www.mozilla.org/MPL/
::
::     Software distributed under the License is distributed on an "AS IS"
::     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
::     License for the specific language governing rights and limitations
::     under the License.
::
::     The Original Code is ThreadFix.
::
::     The Initial Developer of the Original Code is Denim Group, Ltd.
::     Portions created by Denim Group, Ltd. are Copyright (C)
::     Denim Group, Ltd. All Rights Reserved.
::
::     Contributor(s): Denim Group, Ltd.
::
:://////////////////////////////////////////////////////////////////////

:: The scripts included with this project are not intended to be generic.

set OLDDIR=%CD%
CALL vagrant.bat destroy -f
CALL vagrant.bat up
CALL vagrant.bat package
RENAME package.box package-%date:~10,4%%date:~4,2%%date:~7,2%-%time:~0,2%%time:~3,2%%time:~6,2%.box
CALL vagrant.bat up --no-provision

CD C:\Path\To\ThreadFix\Base
SET JAVA_HOME=C:\Path\To\Java
sleep 5
CALL %OLDDIR%\maven_test.bat && chdir /d %OLDDIR%
