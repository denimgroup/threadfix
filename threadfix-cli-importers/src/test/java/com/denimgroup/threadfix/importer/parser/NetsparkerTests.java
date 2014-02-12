package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;

import static com.denimgroup.threadfix.importer.TestConstants.*;
import static junit.framework.Assert.assertNotNull;

// TODO move all the tests to this format.
public class NetsparkerTests {

    public final static String[][] netsparkerResults = new String[] [] {
            {CODE_INJECTION, "Critical", "/demo/EvalInjection2.php", "command"},
            {OS_INJECTION, "Critical", "/demo/OSCommandInjection2Ø´.php", "fileName"},
            {RESOURCE_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
            {XSS, "High", "/demo/EvalInjection2.php", "command"},
            {XSS, "High", "/demo/SQLI2.php", "username"},
            {XSS, "High", "/demo/XPathInjection2.php", "password"},
            {XSS, "High", "/demo/XPathInjection2.php", "username"},
            {XSS, "High", "/demo/XSS-reflected2.php", "username"},
            {SOURCE_CODE_INCLUDE, "Medium", "/demo/OSCommandInjection2.php", "fileName"},
            {CONFIGURATION, "Low", "/demo/", ""},
            {FORCED_BROWSING, "Low", "/demo/LDAPInjection.php", ""},
            {FORCED_BROWSING, "Low", "/demo/PredictableResource.php.bak", ""},
            {INFORMATION_EXPOSURE, "Low", "/demo/", ""},
            {INFORMATION_EXPOSURE, "Low", "/demo/PredictableResource.php", ""},
            {INFO_EXPOSURE_ERROR_MESSAGE, "Low", "/demo/SQLI2.php", "username"},
            {INFORMATION_EXPOSURE, "Info", "/demo/EvalInjection2.php", ""},
            {INFORMATION_EXPOSURE, "Info", "/demo/FormatString2.php", ""},
            {INFORMATION_EXPOSURE, "Info", "/demo/LDAPInjection2.php", ""},
            {INFORMATION_EXPOSURE, "Info", "/demo/OSCommandInjection2.php", ""},
            {INFORMATION_EXPOSURE, "Info", "/demo/PathTraversal.php", ""},
            {INFORMATION_EXPOSURE, "Info", "/demo/SQLI2.php", ""},
            {INFORMATION_EXPOSURE, "Info", "/demo/XPathInjection2.php", ""},
            {INFORMATION_EXPOSURE, "Info", "/demo/XSS-cookie.php", ""},
            {INFORMATION_EXPOSURE, "Info", "/demo/XSS-reflected2.php", ""},
            {"Information Exposure Through Directory Listing", "Info", "/demo/DirectoryIndexing/", ""},
    };

    @Test
    public void netSparkerScanTest() {
        ScanComparisonUtils.compare(netsparkerResults, ScanLocationManager.getRoot() +
                "Dynamic/NetSparker/netsparker-demo-site.xml");
    }

}
