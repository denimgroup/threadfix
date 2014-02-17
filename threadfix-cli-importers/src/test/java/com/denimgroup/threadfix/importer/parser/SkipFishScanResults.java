package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class SkipFishScanResults extends TransactionalTest {

    public final static String[][] skipfishResults = new String [][] {
            {SQLI, "Critical", "/demo/EvalInjection2.php", "command"},
            {SQLI, "Critical", "/demo/LDAPInjection2.php", "username"},
            {SQLI, "Critical", "/demo/SQLI2.php", "username"},
            {IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/EvalInjection2.php","command"},
            {IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/FormatString2.php","name"},
            {IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/PathTraversal.php","action"},
            {IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/XSS-cookie.php","cookie"},
            {IMPROPER_HANDLING_OF_MISSING_VALUES, "High", "/demo/XSS-reflected2.php","username"},
            {PATH_TRAVERSAL, "High", "/demo/PathTraversal.php","action"},
            {XSS, "High", "/demo/XSS-cookie.php","cookie"},
            {XSS, "High", "/demo/XSS-reflected2.php","username"},
            {DIRECTORY_LISTING, "High", "/demo/DirectoryIndexing/",""},
            {INFO_LEAK_SERVER_ERROR, "High", "/demo/SQLI2.php","username"},
            {CSRF, "Medium", "/demo/EvalInjection2.php",""},
            {CSRF, "Medium", "/demo/FormatString2.php",""},
            {CSRF, "Medium", "/demo/LDAPInjection2.php",""},
            {CSRF, "Medium", "/demo/OSCommandInjection2.php",""},
            {CSRF, "Medium", "/demo/SQLI2.php",""},
            {CSRF, "Medium", "/demo/XSS-cookie.php",""},
            {CSRF, "Medium", "/demo/XSS-reflected2.php",""},

    };


    @Test
    public void skipFishScanTest() {
        ScanComparisonUtils.compare(skipfishResults, ScanLocationManager.getRoot() +
                "Dynamic/Skipfish/skipfish-demo-site.zip");
    }
}
