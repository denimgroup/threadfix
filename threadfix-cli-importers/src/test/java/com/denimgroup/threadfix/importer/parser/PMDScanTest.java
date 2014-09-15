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
            {CONFIGURATION, "Medium", "C:\\threadfixWorkspace\\threadfix\\threadfix-main\\src\\main\\java\\com\\denimgroup\\threadfix\\service\\defects\\utils\\hpqc\\infrastructure\\Response.java", "responseData"},
            {CONFIGURATION, "Medium", "C:\\threadfixWorkspace\\threadfix\\threadfix-main\\src\\main\\java\\com\\denimgroup\\threadfix\\service\\defects\\utils\\hpqc\\infrastructure\\Response.java", "responseData"},
            {CONFIGURATION, "Medium", "C:\\threadfixWorkspace\\threadfix\\threadfix-main\\src\\main\\java\\com\\denimgroup\\threadfix\\service\\defects\\utils\\hpqc\\infrastructure\\Response.java", "responseData"},
            {CONFIGURATION, "Medium", "C:\\threadfixWorkspace\\threadfix\\threadfix-main\\src\\main\\java\\com\\denimgroup\\threadfix\\webapp\\controller\\ReportCheckResultBean.java", "reportBytes"},
            {CONFIGURATION, "Medium", "C:\\threadfixWorkspace\\threadfix\\threadfix-main\\src\\main\\java\\com\\denimgroup\\threadfix\\webapp\\controller\\ReportCheckResultBean.java", "reportBytes"},
    };

    @Test
    public void pmdScanTest() {
        String scanResults = ScanLocationManager.getRoot() + "Static/PMD/report.xml";

        ScanComparisonUtils.compare(pmdResults, scanResults);
    }
}
