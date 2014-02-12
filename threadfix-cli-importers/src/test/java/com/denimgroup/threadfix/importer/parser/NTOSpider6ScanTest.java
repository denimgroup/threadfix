package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class NTOSpider6ScanTest {

    public final static String[][] ntoSix = new String [][] {
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/Login.asp", "tfUPass"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/Register.asp", "tfRName"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/showforum.asp", "id"},
            {"Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Critical", "/showthread.asp", "id"},
            {"Improper Restriction of Excessive Authentication Attempts", "Critical", "/Login.asp", "tfUPass"},
            {"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "High", "/Search.asp", "tfSearch"},
            {"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "High", "/Templatize.asp", "item"},
            {"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "High", "/showforum.asp", "id"},
            {"Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "High", "/showthread.asp", "id"},
            {"Integer Overflow or Wraparound", "High", "/showforum.asp", "id"},
            {"Integer Overflow or Wraparound", "High", "/showthread.asp", "id"},
            {"Unprotected Transport of Credentials", "High", "/Login.asp", "N/A"},
            {"Unprotected Transport of Credentials", "High", "/Register.asp", "N/A"},
            {"Exposure of Backup File to an Unauthorized Control Sphere", "Medium", "/robots.txt", "N/A"},
            {"Information Exposure", "Medium", "/Templatize.asp", "N/A"},
            {"Information Exposure", "Medium", "/showforum.asp", "N/A"},
            {"Information Exposure Through Browser Caching", "Medium", "/Login.asp", "N/A"},
            {"Information Exposure Through Browser Caching", "Medium", "/Register.asp", "N/A"},
            {"Information Exposure Through Caching", "Medium", "/Login.asp", "N/A"},
            {"URL Redirection to Untrusted Site ('Open Redirect')", "Medium", "/Logout.asp", "RetURL"},
            {"Cleartext Storage of Sensitive Information", "Low", "/", "N/A"},
            {"Cross-Site Request Forgery (CSRF)", "Low", "/Login.asp", "N/A"},
            {"Cross-Site Request Forgery (CSRF)", "Low", "/Register.asp", "N/A"},
            {"Exposure of Backup File to an Unauthorized Control Sphere", "Low", "/login.asp", "N/A"},
            {"Information Exposure", "Low", "/showthread.asp", "N/A"},
    };

    @Test
    public void ntoSpiderSixScan() {
        ScanComparisonUtils.compare(ntoSix, ScanLocationManager.getRoot() +
                "Dynamic/NTOSpider/VulnerabilitiesSummary6.xml");
    }
}
