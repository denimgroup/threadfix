////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.config.SpringConfiguration;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.WhiteHatMockHttpUtils;
import com.denimgroup.threadfix.importer.interop.RemoteProviderFactory;
import com.denimgroup.threadfix.importer.parser.ThreadFixBridge;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by mac on 6/3/14.
 */
@Component
public class WhiteHatScanParsingTests {

    @Autowired
    RemoteProviderFactory factory = null;
    @Autowired
    ThreadFixBridge bridge = null;

    private RemoteProviderApplication getApplication(String key, String nativeName, RemoteProviderType type) {
        RemoteProviderApplication application = new RemoteProviderApplication();
        application.setNativeName(nativeName);
        application.setRemoteProviderType(type);
        return application;
    }

    public static void test(String nativeName, boolean matchNumbers, String[]... expectedFindings) {
        // @Transactional requires Spring AOP, which requires a Spring Bean. Lots of steps to get DB access
        SpringConfiguration.getContext().getBean(WhiteHatScanParsingTests.class).testInner(nativeName, matchNumbers, expectedFindings);
    }

    /**
     * This method will compare the String[][] of expected findings to the parsed scan contents.
     * @param nativeName The native ID of the whitehat application
     * @param expectedFindings an array of expected findings in { url, vuln type name } format
     */
    @Transactional(readOnly = false)
    public void testInner(String nativeName, boolean matchNumbers, String[][] expectedFindings) {

        assertTrue("Spring config is wrong. Factory was null", factory != null);
        assertTrue("Spring config is wrong. Bridge was null", bridge != null);

        WhiteHatRemoteProvider provider = new WhiteHatRemoteProvider();
        bridge.injectDependenciesManually(provider);

        provider.utils = new WhiteHatMockHttpUtils();

        RemoteProviderType type = new RemoteProviderType();
        type.setApiKey(WhiteHatMockHttpUtils.GOOD_API_KEY);
        type.setMatchSourceNumbers(matchNumbers);

        provider.setRemoteProviderType(type);

        List<Scan> scans = provider.getScans(getApplication(WhiteHatMockHttpUtils.GOOD_API_KEY, nativeName, type));

        assertFalse("Scans were null.", scans == null);
        assertFalse("Scans were empty.", scans.isEmpty());

        List<Finding> extraFindings = list();
        List<String[]> missingFindings = list();
        List<Finding> lastScanFindings = scans.get(scans.size() - 1).getFindings();

        // find unexpected findings
        for (Finding finding : lastScanFindings) {
            boolean matched = false;
            for (String[] expectedFinding : expectedFindings) {
                if (matches(expectedFinding, finding)) { // type
                    matched = true;
                }
            }

            if (!matched) {
                extraFindings.add(finding);
            }
        }

        // find missing expected findings
        for (String[] expectedFinding : expectedFindings) {
            boolean matched = false;
            for (Finding finding : lastScanFindings) {
                if (matches(expectedFinding, finding)) { // type
                    matched = true;
                }
            }

            if (!matched) {
                missingFindings.add(expectedFinding);
            }
        }

        for (String[] finding : missingFindings) {
            System.out.println("Missing " + Arrays.toString(finding));
        }

        for (Finding extraFinding : extraFindings) {
            System.out.println("Extra " + extraFinding);
        }

        assert extraFindings.isEmpty() && missingFindings.isEmpty() :
                "Encountered errors. See above.";

    }

    boolean matches(String[] expected, Finding finding) {
        return (((expected[0] == null && finding.getSurfaceLocation().getPath() == null) ||
                (expected[0] != null && expected[0].equals(finding.getSurfaceLocation().getPath()))) // URL
                && expected[1].equals(finding.getChannelVulnerability().getName())); //type
    }

//    @Test
//    public void testDemoSiteBE() {
//        test("Demo Site BE", 15);
//    }

    @Test
    public void testDemoSitePEMatchingNumbers() {
        test("Demo Site PE", true,
                finding("/", "Cross Site Scripting"),
                finding("/blah", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/xss/dataReceptor2.php", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/xss/simple_xss_no_js.php", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/xss/simple_xss_no_script_2.php", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/xss/simple_xss_no_quotes.php", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/os_commanding/param_osc.php", "Directory Traversal"),
                finding("/", "Directory Indexing"),
                finding("/sitegenerator/vulnerabilities/hiddenfld.jsp", "Insufficient Authentication"),
                finding("/crossdomain.xml", "Insufficient Authorization"),
                finding("/vulnerable-java-web-applications/crossdomain.xml", "Insufficient Authorization"),
                finding("/php-ids/crossdomain.xml", "Insufficient Authorization"),
                finding("/vulnerable-web-applications/vanilla/people.php", "Insufficient Transport Layer Protection"),
                finding("/", "Server Misconfiguration")
                );
    }

    @Test
    public void testDemoSitePEThreadFixNumbers() {
        test("Demo Site PE", false,
                finding("/", "Cross Site Scripting"),
                finding("/blah", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/xss/dataReceptor2.php", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/xss/simple_xss_no_js.php", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/xss/simple_xss_no_script_2.php", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/xss/simple_xss_no_quotes.php", "Cross Site Scripting"),
                finding("/php-ids/w3af/audit/os_commanding/param_osc.php", "Directory Traversal"),
                finding("/w3af/core/maxFileSize/", "Directory Indexing"),
                finding("/w3af/discovery/backdoors/", "Directory Indexing"),
                finding("/w3af/core/fuzzFileContent/.svn/text-base/", "Directory Indexing"),
                finding("/w3af/core/json/services/phpolait/jsolait/lib/", "Directory Indexing"),
                finding("/sitegenerator/vulnerabilities/hiddenfld.jsp", "Insufficient Authentication"),
                finding("/crossdomain.xml", "Insufficient Authorization"),
                finding("/vulnerable-java-web-applications/crossdomain.xml", "Insufficient Authorization"),
                finding("/php-ids/crossdomain.xml", "Insufficient Authorization"),
                finding("/vulnerable-web-applications/vanilla/people.php", "Insufficient Transport Layer Protection"),
                finding("/", "Server Misconfiguration")
                );
    }

//    @Test
//    public void testDemoSitePL() {
//        test("Demo Site PL", 60);
//    }

    @Test
    public void testDemoSiteSEMatching() {
        test("Demo Site SE", true,
                finding("/w3af/bruteforce/formLogin/formLogin.html", "Insufficient Transport Layer Protection"),
                finding("/vulnerable-web-applications/vanilla/people.php", "Insufficient Transport Layer Protection"),
                finding("/vulnerable-web-applications/nanbiquara_v2.0/", "Cross Site Scripting"),
                finding("/php-ids/crossdomain.xml", "Insufficient Authorization")
        );
    }

    @Test
    public void testDemoSiteSEThreadFixStyle() {
        test("Demo Site SE", false,
                finding("/w3af/bruteforce/formLogin/formLogin.html", "Insufficient Transport Layer Protection"),
                finding("/vulnerable-web-applications/vanilla/people.php", "Insufficient Transport Layer Protection"),
                finding("/vulnerable-web-applications/nanbiquara_v2.0/", "Cross Site Scripting"),
                finding("/php-ids/crossdomain.xml", "Insufficient Authorization")
        );
    }

    // best method ever
    private String[] finding(String... args) {
        return args;
    }

}
