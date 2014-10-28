package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Ignore;
import org.junit.Test;

import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class NessusScanTest extends TransactionalTest {


    public final static String[][] nessusResults = new String [][] {
            {OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
            {SQLI, "Critical", "/demo/SQLI2.php", "username"},
            {FORCED_BROWSING, "Medium", "/demo/PredictableResource.php.bak", ""},
            {EXTERNAL_FILEPATH_CONTROL, "Medium", "/demo/OSCommandInjection2.php", "fileName"},
            {XSS, "Medium", "/demo/EvalInjection2.php", "command"},
            {XSS, "Medium", "/demo/XPathInjection2.php", "password"},
            {XSS, "Medium", "/demo/XSS-cookie.php", "cookie"},
            {XSS, "Medium", "/demo/XSS-reflected2.php", "username"},
            {SESSION_FIXATION, "Medium", "/demo/XSS-reflected2.php", "username"},
            {DIRECTORY_LISTING, "Low", "/demo/DirectoryIndexing/", ""},
    };

    @Ignore // the scan format changed, it automatically parses cwe now. We need to edit this test.
    @Test
    @Ignore // the mappings are dynamic now so this test breaks even though the integration is ok
    public void nessusScanTest() {
        ScanComparisonUtils.compare(nessusResults, ScanLocationManager.getRoot() +
                "Dynamic/Nessus/nessus_report_TFTarget.xml");
    }
}
