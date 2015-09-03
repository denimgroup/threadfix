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
package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.Permission;

import static com.denimgroup.threadfix.data.entities.Permission.*;

/**
 * Created by mcollins on 7/27/15.
 */
public enum RestMethod {

    CREATE_FINDING(CAN_MODIFY_VULNERABILITIES, false),

    // Application-level stuff needs to be checked using PermissionUtils
    APPLICATION_DETAIL(READ_ACCESS, false),
    APPLICATION_SET_PARAMS(CAN_MANAGE_APPLICATIONS, true),
    APPLICATION_LOOKUP(READ_ACCESS, false),
    APPLICATION_NEW(CAN_MANAGE_APPLICATIONS, true),
    APPLICATION_SET_WAF(CAN_MANAGE_APPLICATIONS, true),
    APPLICATION_UPLOAD(CAN_UPLOAD_SCANS, false),
    APPLICATION_ATTACH_FILE(CAN_MANAGE_APPLICATIONS, true),
    APPLICATION_SET_URL(CAN_MANAGE_APPLICATIONS, true),
    APPLICATION_UPDATE(CAN_MANAGE_APPLICATIONS, true),
    APPLICATION_ADD_TAG(CAN_MANAGE_APPLICATIONS, true),
    APPLICATION_REMOVE_TAG(CAN_MANAGE_APPLICATIONS, true),
    APPLICATION_SCAN_LIST(READ_ACCESS, false),

    // CWE
    CWE_SET_CUSTOM_TEXT(CAN_MANAGE_CUSTOM_CWE_TEXT, true),

    // PLUGINS
    PLUGIN_MARKERS(READ_ACCESS, false),
    PLUGIN_ENDPOINTS(READ_ACCESS, false),
    PLUGIN_APPLICATIONS(READ_ACCESS, false),

    // Scans--check in its controller
    SCAN_DETAILS(READ_ACCESS, false),

    // Tags
    TAG_CREATE(CAN_MANAGE_TAGS, true),
    TAG_APPLICATION_LIST(CAN_MANAGE_TAGS, true),
    TAG_EDIT(CAN_MANAGE_TAGS, true),
    TAG_LOOKUP(CAN_MANAGE_TAGS, true),
    TAG_DELETE(CAN_MANAGE_TAGS, true),
    TAG_LIST(CAN_MANAGE_TAGS, true),

    // Teams (hybrid)
    TEAM_LOOKUP(READ_ACCESS, false),
    TEAM_NEW_APPLICATION(CAN_MANAGE_APPLICATIONS, true),
    TEAM_NEW(CAN_MANAGE_TEAMS, true),
    TEAM_LIST(READ_ACCESS, false),
    TEAM_UPDATE(CAN_MANAGE_TEAMS, true),

    // Vuln Search (needs to apply search stuff)
    VULNERABILITY_SEARCH(CAN_GENERATE_REPORTS, false),

    // WAFs
    WAF_LIST(CAN_MANAGE_WAFS, true),
    WAF_DETAIL(CAN_MANAGE_WAFS, true),
    WAF_LOOKUP(CAN_MANAGE_WAFS, true),
    WAF_RULES(CAN_GENERATE_WAF_RULES, true),
    WAF_NEW(CAN_MANAGE_WAFS, true),
    WAF_LOG(CAN_MANAGE_WAFS, true),

    // Scan Agents
    OPERATION_REQUEST_SCAN_AGENT_KEY(CAN_MANAGE_SCAN_AGENTS, true),
    OPERATION_SET_TASK_CONFIG(CAN_MANAGE_SCAN_AGENTS, true),
    OPERATION_COMPLETE_TASK(CAN_MANAGE_SCAN_AGENTS, true),
    OPERATION_TASK_STATUS_UPDATE(CAN_MANAGE_SCAN_AGENTS, true),
    OPERATION_REQUEST_TASK(CAN_MANAGE_SCAN_AGENTS, true),
    OPERATION_QUEUE_SCAN(CAN_MANAGE_SCAN_AGENTS, true),
    ;

    public final Permission permission;
    public final boolean restricted;

    RestMethod(Permission permission, boolean restricted) {
        this.permission = permission;
        this.restricted = restricted;
    }
}
