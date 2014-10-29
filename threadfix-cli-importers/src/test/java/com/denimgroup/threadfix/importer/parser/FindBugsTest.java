package com.denimgroup.threadfix.importer.parser;

import com.denimgroup.threadfix.importer.ScanLocationManager;
import com.denimgroup.threadfix.importer.TransactionalTest;
import com.denimgroup.threadfix.importer.utils.ScanComparisonUtils;
import org.junit.Test;
import static com.denimgroup.threadfix.importer.TestConstants.*;

/**
 * Created by denimgroup on 2/10/14.
 */
public class FindBugsTest extends TransactionalTest {

    public final static String[][] findBugsResults = new String[] []{
            { XSS, "Critical", "securibench/micro/aliasing/Aliasing1.java", "name"},
            { XSS, "Critical", "securibench/micro/aliasing/Aliasing4.java", "name"},
            { XSS, "Critical", "securibench/micro/basic/Basic1.java", "str"},
            { XSS, "Critical", "securibench/micro/basic/Basic18.java", "s"},
            { XSS, "Critical", "securibench/micro/basic/Basic2.java", "str"},
            { XSS, "Critical", "securibench/micro/basic/Basic28.java", "name"},
            { XSS, "Critical", "securibench/micro/basic/Basic4.java", "str"},
            { XSS, "Critical", "securibench/micro/basic/Basic8.java", "str"},
            { XSS, "Critical", "securibench/micro/basic/Basic9.java", "s1"},
            { XSS, "Critical", "securibench/micro/pred/Pred4.java", "name"},
            { XSS, "Critical", "securibench/micro/pred/Pred5.java", "name"},
            { XSS, "Critical", "securibench/micro/pred/Pred6.java", "name"},
            { XSS, "Critical", "securibench/micro/pred/Pred7.java", "name"},
            { XSS, "Critical", "securibench/micro/pred/Pred8.java", "name"},
            { XSS, "Critical", "securibench/micro/pred/Pred9.java", "name"},
            { XSS, "Critical", "securibench/micro/session/Session1.java", "name"},
            { XSS, "Critical", "securibench/micro/session/Session2.java", "name"},
            { XSS, "High", "securibench/micro/basic/Basic10.java", "s5"},
            { XSS, "High", "securibench/micro/basic/Basic27.java", ""},
            { XSS, "High", "securibench/micro/basic/Basic29.java", ""},
            { XSS, "High", "securibench/micro/basic/Basic30.java", ""},
            { XSS, "High", "securibench/micro/basic/Basic32.java", "header"},
            { XSS, "High", "securibench/micro/basic/Basic34.java", "headerValue"},
            { XSS, "High", "securibench/micro/basic/Basic35.java", ""},
            { XSS, "High", "securibench/micro/pred/Pred2.java", "name"},
            { XSS, "High", "securibench/micro/pred/Pred3.java", "name"},
            { XSS, "High", "securibench/micro/strong_updates/StrongUpdates3.java", ""},
            { XSS, "High", "securibench/micro/strong_updates/StrongUpdates4.java", ""},
            { XSS, "High", "securibench/micro/strong_updates/StrongUpdates5.java", ""},
            { SQLI, "High", "securibench/micro/basic/Basic19.java", ""},
            { SQLI, "High", "securibench/micro/basic/Basic20.java", ""},
            { SQLI, "High", "securibench/micro/basic/Basic21.java", ""},


    };

    @Test
    public void findBugsScanTest() {
        ScanComparisonUtils.compare(findBugsResults, ScanLocationManager.getRoot() +
                "Static/FindBugs/findbugs-normal.xml");
    }

}
