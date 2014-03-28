package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;

import static com.denimgroup.threadfix.importer.TestConstants.*;

/**
 * Created by denimgroup on 2/10/14.
 */
public class CenzicScanTest extends TransactionalTest {

    public final static String[][] cenzicResults = new String [][] {
            {XSS, "High", "/Kelev/php/accttransaction.php", "FromDate"},
            {XSS, "High", "/Kelev/php/accttransaction.php", "ToDate"},
            {XSS, "High", "/Kelev/php/loanrequestdetail.php", "hUserId"},
            {XSS, "High", "/Kelev/php/login.php", "hUserType"},
            {XSS, "High", "/Kelev/register/register.php", "UserId"},
            {XSS, "High", "/Kelev/view/updateloanrequest.php", "txtAnnualIncome"},
            {XSS, "High", "/Kelev/view/updateloanrequest.php", "txtFirstName"},
            {XSS, "High", "/tracker/rest/gadget/1.0/project/generate", "projectsOrCategories"},
    };

    @Test
     public void cenzicScanTest() {
        ScanComparisonUtils.compare(cenzicResults, ScanLocationManager.getRoot() +
                "Dynamic\\CenzicHailstorm\\ReportItem_2013-06-21_09-14.xml");
    }
}
