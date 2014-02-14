package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;
public class ZapProxyScanTest extends TransactionalTest {

    public final static String[][] zapProxyResults = new String [][] {
            {DIRECTORY_LISTING, "Medium", "/demo/DirectoryIndexing/", ""},
            {XSS, "High", "/demo/EvalInjection2.php", "command"},
            {XSS, "High", "/demo/XPathInjection2.php", "username"},
            {SQLI, "High", "/demo/SQLI2.php", "username"},
            {SQLI, "High", "/demo/SQLI2.php", "username"},
    };

    @Test
    public void zapProxyScanTest() {
        ScanComparisonUtils.compare(zapProxyResults, ScanLocationManager.getRoot() +
                "Dynamic/ZAP/zaproxy-normal.xml");
    }
}
