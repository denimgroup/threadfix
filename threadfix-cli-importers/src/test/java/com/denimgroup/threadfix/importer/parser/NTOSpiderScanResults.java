package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
/**
 * Created by denimgroup on 2/10/14.
 */
public class NTOSpiderScanResults extends TransactionalTest {

    public final static String[][] ntospiderResults = new String [][] {
            {"Improper Authentication", "Critical", "/bank/login.aspx", ""},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/bank/login.aspx", "passw"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/bank/login.aspx", "uid"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/subscribe.aspx", "txtEmail"},
            {"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "High", "/bank/login.aspx", "uid"},
            {"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "High", "/comment.aspx", "name"},
            {"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "High", "/notfound.aspx", "aspxerrorpath"},
            {"Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)", "High", "/search.aspx", "txtSearch"},
            {"Information Exposure Through Directory Listing", "Medium", "/bank/", ""},
            {"Privacy Violation", "Medium", "/", ""},
            {"Privacy Violation", "Medium", "/bank/login.aspx", ""},
            {"Privacy Violation", "Medium", "/comment.aspx", ""},
            {"Privacy Violation", "Medium", "/default.aspx", ""},
            {"Privacy Violation", "Medium", "/disclaimer.htm", ""},
            {"Privacy Violation", "Medium", "/feedback.aspx", ""},
            {"Privacy Violation", "Medium", "/notfound.aspx", ""},
            {"Privacy Violation", "Medium", "/search.aspx", ""},
            {"Privacy Violation", "Medium", "/subscribe.aspx", ""},
            {"Privacy Violation", "Medium", "/survey_questions.aspx", ""},
            {"Information Exposure Through Environmental Variables", "Low", "/aaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbthbbbbbbbbbbbbb.bbbbbbb", ""},
    };

    @Test
    public void ntoSpiderScanTest() {
        ScanComparisonUtils.compare(ntospiderResults, ScanLocationManager.getRoot() +
                "Dynamic/NTOSpider/VulnerabilitiesSummary.xml");
    }
}
