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
    APPLICATION_DETAIL(false),
    APPLICATION_SET_PARAMS(true),
    APPLICATION_LOOKUP(false),
    APPLICATION_NEW(true),
    APPLICATION_SET_WAF(true),
    APPLICATION_UPLOAD(true),
    APPLICATION_ATTACH_FILE(true),
    APPLICATION_SET_URL(true),
    APPLICATION_UPDATE(true),
    APPLICATION_ADD_TAG(true),
    APPLICATION_REMOVE_TAG(true),
    APPLICATION_SCAN_LIST(false),

    // CWE
    CWE_SET_CUSTOM_TEXT(CAN_MANAGE_CUSTOM_CWE_TEXT, true),

    // PLUGINS
    PLUGIN_MARKERS(false),
    PLUGIN_ENDPOINTS(false),
    PLUGIN_APPLICATIONS(false),

    // Scans--check in its controller
    SCAN_DETAILS(false),

    // Tags
    TAG_CREATE(CAN_MANAGE_TAGS, true),
    TAG_EDIT(CAN_MANAGE_TAGS, true),
    TAG_LOOKUP(CAN_MANAGE_TAGS, true),
    TAG_DELETE(CAN_MANAGE_TAGS, true),
    TAG_LIST(CAN_MANAGE_TAGS, true),

    // Teams (hybrid)
    TEAM_LOOKUP(false),
    TEAM_NEW_APPLICATION(true),
    TEAM_NEW(CAN_MANAGE_TEAMS, true),
    TEAM_LIST(false),
    TEAM_UPDATE(true),

    // Vuln Search (needs to apply search stuff)
    VULNERABILITY_SEARCH(false),

    // WAFs
    WAF_LIST(Permission.CAN_MANAGE_WAFS, true),
    WAF_DETAIL(Permission.CAN_MANAGE_WAFS, true),
    WAF_LOOKUP(Permission.CAN_MANAGE_WAFS, true),
    WAF_RULES(Permission.CAN_MANAGE_WAFS, true),
    WAF_NEW(Permission.CAN_MANAGE_WAFS, true),
    WAF_LOG(Permission.CAN_MANAGE_WAFS, true)
    ;

    Permission permission;
    boolean restricted;

    RestMethod(Permission permission, boolean restricted) {
        this.permission = permission;
        this.restricted = restricted;
    }

    RestMethod(boolean restricted) {
        this.restricted = restricted;
    }
}
