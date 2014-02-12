package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;
/**
 * Created by denimgroup on 2/10/14.
 */
public class ArachniScanTest {


    public final static String[][] arachniResults = new String [][] {
            {XSS, "Critical", "/demo/EvalInjection2.php", "command"},
            {XSS, "Critical", "/demo/XPathInjection2.php", "password"},
            {XSS, "Critical", "/demo/XPathInjection2.php", "username"},
            {XSS, "Critical", "/demo/XSS-reflected2.php", "username"},
            {LDAP_INJECTION, "Critical", "/demo/LDAPInjection2.php", "username"},
            {OS_INJECTION, "Critical", "/demo/OSCommandInjection2.php", "fileName"},
            {SQLI, "Critical", "/demo/SQLI2.php", "username"},
            {XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "password"},
            {XML_INJECTION, "Critical", "/demo/XPathInjection2.php", "username"},
            {INFO_LEAK_DIRECTORIES, "High", "/demo/", ""},
    };

    @Test
    public void arachniScanTest() {
        ScanComparisonUtils.compare(arachniResults, ScanLocationManager.getRoot() +
                "Dynamic/Arachni/php-demo.xml");
    }
}
