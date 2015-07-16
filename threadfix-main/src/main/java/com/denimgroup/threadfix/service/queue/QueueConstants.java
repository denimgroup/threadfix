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
package com.denimgroup.threadfix.service.queue;

/**
 * @author bbeverly
 * 
 */
public interface QueueConstants {

	static final String DEFECT_TRACKER_SYNC_REQUEST = "DEFECT_TRACKER_SYNC_REQUEST";
	static final String IMPORT_SCANS_REQUEST = "IMPORT_SCANS_REQUEST";

	static final String IMPORT_REMOTE_PROVIDER_SCANS_REQUEST = "IMPORT_REMOTE_PROVIDER_SCANS_REQUEST";
	static final String NORMAL_SCAN_TYPE = "Scan";
	static final String DEFECT_TRACKER_VULN_UPDATE_TYPE = "Defect Tracker Vuln Update";
	static final String GRC_CONTROLS_UPDATE_TYPE = "GRC Controls Update";
	static final String SEND_EMAIL_REPORT = "Send Email Report";
	static final String SUBMIT_DEFECT_TYPE = "Submit Defect";
    static final String SCHEDULED_SCAN_TYPE = "Scheduled Scan";

    static final String STATISTICS_UPDATE = "Statistics Update";

	static final String STATISTICS_TEAM_UPDATE = "Statistics Team Update";

    static final String VULNS_FILTER = "Vulnerabilities Filter";

}
