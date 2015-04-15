////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.csv2ssl.util;

/**
 * Created by mcollins on 1/22/15.
 */
public enum Header {
    SEVERITY(Strings.SEVERITY, "Severity (One of 'Information', 'Low', 'Medium', 'High', 'Critical' or a number from 1 to 5)"),
    CWE(Strings.CWE, "CWE (number, ex. 79)"),
    SOURCE(Strings.SOURCE, "Source (Origin of finding ex. Manual Testing"),
    URL(Strings.URL, "Path (String, ex. /login.jsp)"),
    PARAMETER(Strings.PARAMETER, "Parameter (String, ex. username)"),
    NATIVE_ID(Strings.NATIVE_ID, "ID (identifying String, ex. 72457)"),
    SHORT_DESCRIPTION(Strings.SHORT_DESCRIPTION, "Short Description"),
    LONG_DESCRIPTION(Strings.LONG_DESCRIPTION, "Long Description"),
    ISSUE_ID(Strings.ISSUE_ID, "Issue ID(Jira, TFS, etc. ID format)"),
    FINDING_DATE(Strings.FINDING_DATE, "Finding Date (Must be in the format " + Strings.DATE_FORMAT + ")"),
    SOURCE_FILE_NAME(Strings.SOURCE_FILE_NAME, "Source File (String, ex. testFile.jsp)");

    public final String text, description;

    Header(String text, String description) {
        this.text = text;
        this.description = description;
    }
}
