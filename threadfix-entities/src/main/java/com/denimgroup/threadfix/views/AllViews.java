package com.denimgroup.threadfix.views;

public class AllViews {

    public static interface TableRow {}

    public static interface FormInfo {}

    public static interface VulnerabilityDetail {}

    public static interface VulnSearch {}

    public static interface UIVulnSearch extends VulnSearch {}

    public static interface RestVulnSearch extends UIVulnSearch, RestView2_1 {}

    public static interface RestView {}

    public static interface RestView2_1 extends RestView {}

    public static interface RestViewTeam2_1 extends RestView2_1 {}

    public static interface RestViewWaf2_1 extends RestView2_1 {}

    public static interface RestViewApplication2_1 extends RestView2_1 {}

    public static interface RestViewScan2_1 extends RestView2_1 {}

    public static interface RestViewScanStatistic {}

    public static interface RestViewTag {}

    // this is just for one property really
    public static interface VulnSearchApplications {}

}
