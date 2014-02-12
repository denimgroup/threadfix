package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;

/**
 * Created by denimgroup on 2/10/14.
 */
public class CatNetTests {

    public final static String[][] catnetResults = {
            { XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "email"},
            { XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "txtMessage"},
            { XSS, "Critical", "/ZigguratUtilityWeb/ContactUs.aspx", "txtSubject"},
            { XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtAmount"},
            { XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtAmount"},
            { XSS, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtCardNumber"},
            { XSS, "Critical", "/ZigguratUtilityWeb/Message.aspx", "Msg"},
            { SQLI, "Critical", "/ZigguratUtilityWeb/LoginPage.aspx", "txtPassword"},
            { SQLI, "Critical", "/ZigguratUtilityWeb/LoginPage.aspx", "txtUsername"},
            { SQLI, "Critical", "/ZigguratUtilityWeb/MakePayment.aspx", "txtAmount"},
            { SQLI, "Critical", "/ZigguratUtilityWeb/ViewStatement.aspx", "StatementID"},
    };

    @Test
    public void catNetTests() {
        ScanComparisonUtils.compare(catnetResults, ScanLocationManager.getRoot() +
                "Static/CAT.Net/catnet_RiskE.xml");
    }

}