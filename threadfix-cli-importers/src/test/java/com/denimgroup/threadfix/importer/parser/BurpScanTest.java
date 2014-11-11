package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class BurpScanTest extends TransactionalTest {

    public final static String[][] burpResults = new String [][] {
            {XSS, "High", "/demo/EvalInjection2.php", "command"},
            {XSS, "High", "/demo/XSS-reflected2.php", "username"},
            {OS_INJECTION, "High", "/demo/OSCommandInjection2.php", "fileName"},
            {SQLI, "High", "/demo/SQLI2.php", "username"},
            {IMPROPER_CROSS_BOUNDARY_REMOVAL_OF_DATA, "Info", "/demo/PredictableResource.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/DirectoryIndexing/admin.txt", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/EvalInjection.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/EvalInjection2.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/FormatString.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/FormatString2.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/LDAPInjection.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/LDAPInjection2.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/OSCommandInjection.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/OSCommandInjection2.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/PathTraversal.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/PredictableResource.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/SQLI.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/SQLI2.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XPathInjection.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XPathInjection2.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-cookie.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-reflected.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-reflected2.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS-stored.php", ""},
            {FAILURE_TO_HANDLE_ENCODING, "Info", "/demo/XSS.php", ""},
            {INFORMATION_EXPOSURE, "Info", "/",""},
            {DIRECTORY_LISTING,"Info","/demo/DirectoryIndexing/",""},
    };

    @Test
    public void burpScanTest() {
        ScanComparisonUtils.compare(burpResults, ScanLocationManager.getRoot() +
                "Dynamic/Burp/burp-demo-site.xml");
    }

    public final static String[][] sbirResults = new String [][] {
            {XSS, "High", "/Test/WebForm1.aspx", "newitem"},
    };

    @Test
    public void burpScanTest2() {
        ScanComparisonUtils.compare(sbirResults, ScanLocationManager.getRoot() +
                "SBIR/webform.xml");
    }
}
