package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;

/**
 * Created by mhatzenbuehler on 7/10/2014.
 */
public class PMDScanTest extends TransactionalTest{
    //cwe name, severity, path, parameter
    public final static String[][] pmdResults = new String [][] {
            {CONFIGURATION, "Medium", "/pmd-5.1.1/rules/java/sunsecure.html", "responseData"},
            {CONFIGURATION, "Medium", "/pmd-5.1.1/rules/java/sunsecure.html", "responseData"},
            {CONFIGURATION, "Medium", "/pmd-5.1.1/rules/java/sunsecure.html", "responseData"},
            {CONFIGURATION, "Medium", "/pmd-5.1.1/rules/java/sunsecure.html", "responseData"},
            {CONFIGURATION, "Medium", "/pmd-5.1.1/rules/java/sunsecure.html", "responseData"},
            {CONFIGURATION, "Medium", "/pmd-5.1.1/rules/java/sunsecure.html", "responseData"},
    };

    @Test
    public void pmdScanTest() {
        String scanResults = ScanLocationManager.getRoot() + "Static/PMD/report.xml";

        ScanComparisonUtils.compare(pmdResults, scanResults);
    }
}
