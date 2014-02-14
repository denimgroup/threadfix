package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;

public class CatNetTests extends TransactionalTest {

    public final static String[][] catnetResults = {
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\ContactUs.aspx.cs", "email"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\ContactUs.aspx.cs", "txtMessage"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\ContactUs.aspx.cs", "txtSubject"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\MakePayment.aspx.cs", "txtAmount"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\MakePayment.aspx.cs", "txtAmount"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\MakePayment.aspx.cs", "txtCardNumber"},
            { XSS, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\Message.aspx", "Msg"},
            { SQLI, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\LoginPage.aspx.cs", "txtPassword"},
            { SQLI, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\LoginPage.aspx.cs", "txtUsername"},
            { SQLI, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\MakePayment.aspx.cs", "txtAmount"},
            { SQLI, "Critical", "c:\\Project_Archive\\Ziggurat\\ZigguratUtility\\ZigguratUtilityWeb\\ViewStatement.aspx.cs", "StatementID"},
    };

    @Test
    public void catNetTests() {
        ScanComparisonUtils.compare(catnetResults, ScanLocationManager.getRoot() +
                "Static/CAT.NET/catnet_RiskE.xml");
    }

}