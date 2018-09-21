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
package com.denimgroup.threadfix.importer.impl.upload.fortify;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 2/16/15.
 */
class RegexMaps {

    // TODO run through more files and determine whether this method is still valuable
    // or whether we can use only the 'action' parameter and the column parsing.
    static final Map<String, String> FACT_REGEX_MAP = map();
    static final Map<String, String> SPECIAL_REGEX_MAP = map();
    static {
        FACT_REGEX_MAP.put("Direct : System.Web.HttpRequest.get_Item",
                "Request\\[\"([a-zA-Z0-9_]+)\"\\]");
        FACT_REGEX_MAP.put("Direct : System.Web.UI.WebControls.TextBox.get_Text",
                "([a-zA-Z0-9_]+)\\.Text");
        FACT_REGEX_MAP.put("Direct : javax.servlet.ServletRequest.getParameter",
                "getParameter\\(\"([a-zA-Z0-9_]+)\"\\)");
        FACT_REGEX_MAP.put("Direct : System.Data.Common.DbDataReader.get_Item",
                "reader\\[\"([a-zA-Z0-9_]+)\"\\]");
        FACT_REGEX_MAP.put("Direct : System.Web.UI.WebControls.Label.set_Text",
                "^\\s*([a-zA-Z0-9_]+).Text");
        FACT_REGEX_MAP.put("Direct : Customer.HydrateCustomer",
                "Customer.HydrateCustomer\\(([a-zA-Z0-9_]+)\\)");
        FACT_REGEX_MAP.put("get_Item(return)", "Request\\[\"([a-zA-Z0-9_]+)\"\\]");
        FACT_REGEX_MAP.put("get_Item()", "Request\\[\"([a-zA-Z0-9_]+)\"\\]");
        FACT_REGEX_MAP.put("get_Item(...) : HttpSessionState.get_Item may return NULL",
                "Session\\[\"?([a-zA-Z0-9_]+)\"?\\]");
        FACT_REGEX_MAP.put("get_Text(return)", "([a-zA-Z0-9_]+).Text");
        FACT_REGEX_MAP.put("get_QueryString(return)", "Session\\[\"?([a-zA-Z0-9_]+)\"?\\]");
        FACT_REGEX_MAP.put("WEB, XSS",
                "action=\\\"<\\%= ?Request.([a-zA-Z0-9_]+) ?\\%>\\\"");
        FACT_REGEX_MAP.put("Direct : builtin_echo",
                "POST\\[\"?([a-zA-Z0-9_]+)\"?\\]");// TODO LOOK AT THIS
        FACT_REGEX_MAP.put("Direct : System.Web.HttpRequest.get_RawUrl",
                "Request.([a-zA-Z0-9_]+)");
        FACT_REGEX_MAP.put("Name: System.Web.SessionState.HttpSessionState.set_Item",
                " *([a-zA-Z0-9_\\.]+\\[\\\"[a-zA-Z0-9_]+\\\"\\])");
        FACT_REGEX_MAP.put("Direct : System.IO.TextWriter.Write",
                "<% ?=? ?([a-zA-Z0-9_]+) ?%>");
        FACT_REGEX_MAP.put("ReadToEnd()", "([a-zA-Z0-9_]+)\\.ReadToEnd\\(\\)");
        FACT_REGEX_MAP.put("GetSqlStringCommand()",
                "Database\\.GetSqlStringCommand\\(([a-zA-Z0-9_]+)");
        FACT_REGEX_MAP.put("Direct : System.Web.SessionState.HttpSessionState.set_Item",
                "Session\\[\"?([a-zA-Z0-9_]+)\"?\\]");
        FACT_REGEX_MAP.put("read request",
                "[rR]equest\\.?[a-zA-Z_]*\\(\\\"?([a-zA-Z0-9_]+)\\\"?\\)");
        FACT_REGEX_MAP.put("Direct : connection.execute",
                "\\.[eE]xecute\\(([a-zA-Z0-9_]+)\\)");
        FACT_REGEX_MAP.put("Direct : response.write",
                "<\\% ?=? ?([ a-zA-Z0-9_\\.\\\"\\(\\)]+) ?\\%>\\\"");
        FACT_REGEX_MAP.put("Direct : fopen",
                "fopen\\(\"?($?[a-zA-Z0-9_]+)\"?\\)");
        FACT_REGEX_MAP.put("Direct : system",
                "system\\(\"?($?[a-zA-Z0-9_]+)\"?\\)");
        FACT_REGEX_MAP.put("Direct : System.Data.SqlClient.SqlCommand.SqlCommand",
                "SqlCommand\\($?\"?([a-zA-Z0-9_]+)\"?\\)");

        SPECIAL_REGEX_MAP.put("get_Item", "\\[\"?([a-zA-Z0-9_]+)\"?\\]");
        SPECIAL_REGEX_MAP.put("get_Item()", "\\[\"?([a-zA-Z0-9_]+)\"?\\]");
        SPECIAL_REGEX_MAP.put("get_Text", "=.*?([a-zA-Z0-9_]+)\\.[tT]ext");
        SPECIAL_REGEX_MAP.put("get_Text()", "=.*?([a-zA-Z0-9_]+)\\.[tT]ext");
        SPECIAL_REGEX_MAP.put("Write", "\\[\"?([a-zA-Z0-9_]+)\"?\\]");
        SPECIAL_REGEX_MAP.put("getParameter", "getParameter\\(\"([a-zA-Z0-9\\._]+)\"\\)");
        SPECIAL_REGEX_MAP.put("getHeader", "getHeader\\(\"([a-zA-Z0-9\\._]+)\"\\)");
    }
}
