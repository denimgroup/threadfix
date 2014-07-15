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
    public final static String[][] pmdResults = new String [][] {
            //cwe name, severity, path, parameter
            { CONFIGURATION, "Medium", "ArrayIsStoredDirectly", "responseData"},
            { CONFIGURATION, "Medium", "ArrayIsStoredDirectly", "responseData"},
            { CONFIGURATION, "Medium", "ArrayIsStoredDirectly", "responseData"},
            { CONFIGURATION, "Medium", "ArrayIsStoredDirectly", "responseData"},
            { CONFIGURATION, "Medium", "ArrayIsStoredDirectly", "responseData"},
            { CONFIGURATION, "Medium", "ArrayIsStoredDirectly", "responseData"},
    };

    @Test
    public void pmdScanTest() {
        ScanComparisonUtils.compare(pmdResults, ScanLocationManager.getRoot() +
                                    "Static/PMD/report.xml");
    }
}
