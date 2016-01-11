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

package com.denimgroup.threadfix.views;

public class AllViews {

    public static interface TableRow {}

    public static interface FormInfo {}

    public static interface GRCToolsPage extends FormInfo {}

    public static interface VulnerabilityDetail extends FormInfo {}

    public static interface VulnSearch {}

    public static interface RestVulnSearchWithCustomText extends RestVulnSearch {}

    public static interface UIVulnSearch extends VulnSearch {}

    public static interface RestVulnSearch extends RestView2_1 {}

    public static interface RestView {}

    public static interface RestView2_1 extends RestView {}

    public static interface RestViewTeam2_1 extends RestView2_1 {}

    public static interface RestViewTeams2_1 extends RestView2_1 {}

    public static interface RestViewWaf2_1 extends RestView2_1 {}

    public static interface RestViewWafs2_1 extends RestView2_1 {}

    public static interface RestViewApplication2_1 extends RestView2_1 {}

    public static interface RestCreateApplication2_1 extends RestView2_1 {}

    public static interface RestViewScan2_1 extends RestView2_1 {}

    public static interface RestViewScanStatistic {}

    public static interface RestViewTag {}

    public static interface DefectTrackerInfos {}

    // this is just for one property really
    public static interface VulnSearchApplications {}

    public static interface RestViewScanList {}

    public static interface RestCweView {}

    public static interface ApplicationIndexView {}

    public static interface ScheduledEmailReportView {}

    public static interface PolicyPageView {}

    public static interface HistoryView {}

    public static interface OrganizationHistoryView extends HistoryView {}

    public static interface ApplicationHistoryView extends HistoryView {}

    public static interface VulnerabilityHistoryView extends HistoryView {}

    public static interface UserHistoryView extends HistoryView {}

    public interface SharedVulnerabilityView extends VulnerabilityDetail {}
}
