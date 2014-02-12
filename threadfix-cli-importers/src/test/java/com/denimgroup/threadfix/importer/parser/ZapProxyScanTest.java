package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class ZapProxyScanTest {

    public final static String[][] zapProxyResults = new String [][] {
            {DIRECTORY_LISTING, "High", "/demo/DirectoryIndexing/", ""},
            {XSS, "Medium", "/demo/EvalInjection2.php", "command"},
            {XSS, "Medium", "/demo/XPathInjection2.php", "password"},
            {XSS, "Medium", "/demo/XPathInjection2.php", "username"},
            {XSS, "Medium", "/demo/XSS-reflected2.php", "username"},
            {SQLI, "Medium", "/demo/SQLI2.php", "username"},
    };

    @Test
    public void zapProxyScanTest() {
        ScanComparisonUtils.compare(zapProxyResults, ScanLocationManager.getRoot() +
                "Dynamic/ZAP/zaproxy-normal.xml");
    }
}
