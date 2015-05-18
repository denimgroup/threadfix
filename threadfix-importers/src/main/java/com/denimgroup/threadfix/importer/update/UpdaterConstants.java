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
package com.denimgroup.threadfix.importer.update;

/**
 * Created by mac on 9/12/14.
 */
public final class UpdaterConstants {

    private UpdaterConstants() {}

    public static final String
            DEFECT_TRACKERS_FOLDER = "mappings/defect",
            GENERIC_VULNS_FOLDER = "mappings/generic",
            SCANNERS_FOLDER = "mappings/scanner",
            WAFS_FOLDER = "mappings/waf",
            REMOTE_PROVIDERS_FOLDER = "mappings/remoteprovider",
            DEFAULT_TAGS_FOLDER = "mappings/defaultTag",
            DATE_PATTERN = "MM/dd/yyyy hh:mm:ss";

}
