package com.denimgroup.threadfix.scanagent.util;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import junit.framework.TestCase;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.jetbrains.annotations.Nullable;
import org.junit.*;

import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/18/13
 * Time: 2:32 PM
 * To change this template use File | Settings | File Templates.
 */
public class ConfigurationUtilsTests extends TestCase {

    private static final String FAKE_URL = "fakeUrl";
    private static final String REAL_URL = "http://localhost:8080/threadfix/rest";
    private static final String FAKE_API_KEY = "fakeAPIKey";
    private static final String REAL_API_KEY = "N5bfcd6L00QLR5jdsaA76YEtkZ7LEWotk43AjOkfmoo";
    private static final String FAKE_WORK_DIR = "C:\\Users";
    private static final String REAL_WORK_DIR = "C:\\Users\\stran\\Desktop\\Acunetix";

    @Nullable
    private static  PropertiesConfiguration config = getPropertiesFile();

    @Nullable
    private static PropertiesConfiguration getPropertiesFile() {
        PropertiesConfiguration config = null;
        try {
            System.out.println(System.getProperty("user.dir")) ;
            config = new PropertiesConfiguration("scanagent.properties");
            config.setAutoSave(true);
        } catch (ConfigurationException e) {
           System.out.println("Error reading properties file");
        }
        return config;
    }


//    @BeforeClass
//    public static void oneTimeSetUp() {
//        try {
//            System.out.println(System.getProperty("user.dir")) ;
//            config = new PropertiesConfiguration("scanagent.properties");
//            config.setAutoSave(true);
//        } catch (ConfigurationException e) {
//            System.out.println("Error reading properties file");
//        }
//    }

    @After
    public void tearDown() {
        config.setProperty("scanagent.threadFixServerUrl", REAL_URL);
        config.setProperty("scanagent.threadFixApiKey", REAL_API_KEY);
        config.setProperty("scanagent.baseWorkDir", REAL_WORK_DIR);
        config.setProperty("zap.scanName", "OWASP Zed Attack Proxy");
        config.setProperty("zap.scanVersion", "2.2.2");
        config.setProperty("zap.scanExecutablePath", "C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy\\");
        config.setProperty("zap.scanHost", "localhost");
        config.setProperty("zap.scanPort", "8090");
    }

//    @Before
//    public void setUp() {
//        config.setProperty("scanagent.threadFixServerUrl", REAL_URL);
//        config.setProperty("scanagent.threadFixApiKey", REAL_API_KEY);
//        config.setProperty("scanagent.baseWorkDir", REAL_WORK_DIR);
//    }

    @Test
    public void testSaveUrlConfig() {
        ConfigurationUtils.saveUrlConfig(FAKE_URL, config);
        Assert.assertEquals(FAKE_URL, config.getString("scanagent.threadFixServerUrl"));
    }

    @Test
    public void testSaveKeyConfig() {
        ConfigurationUtils.saveKeyConfig(FAKE_API_KEY, config);
        Assert.assertEquals(FAKE_API_KEY, config.getString("scanagent.threadFixApiKey"));
    }

    @Test
    public void testSaveWorkDirectory() {
        ConfigurationUtils.saveWorkDirectory(FAKE_WORK_DIR, config);
        Assert.assertEquals(FAKE_WORK_DIR, config.getString("scanagent.baseWorkDir"));
    }

    @Test
    public void testSaveScannerType() {
        String scanName = "OWASP Zed Attack Proxy";
        String scanVersion = "2.0.0";
        String scanDir = "C:\\Program Files (x86)\\OWASP";
        String scanHost = "google.com";
        int scanPort = 8010;
        Scanner scan = new Scanner(scanName,scanVersion, scanDir, scanHost, scanPort);
        ConfigurationUtils.saveScannerType(scan, config);
        Assert.assertEquals(scanName, config.getString("zap.scanName"));
        Assert.assertEquals(scanVersion, config.getString("zap.scanVersion"));
        Assert.assertEquals(scanDir, config.getString("zap.scanExecutablePath"));
        Assert.assertEquals(scanHost, config.getString("zap.scanHost"));
        Assert.assertEquals(String.valueOf(scanPort), config.getString("zap.scanPort"));

    }

    @Test
    public void testReadAllScanner() {
        List<Scanner> scans = ConfigurationUtils.readAllScanner(config);
        assertEquals(1, scans.size());
        assertEquals("OWASP Zed Attack Proxy", scans.get(0).getName());
    }

    @Test
    public void testIsDirectory() {
        String good_dir = "C:\\Program Files (x86)";
        String bad_dir = "ZAPFolder";
        boolean isDir = ConfigurationUtils.isDirectory(good_dir);
        boolean isNotDir = ConfigurationUtils.isDirectory(bad_dir);
        Assert.assertTrue(isDir);
        Assert.assertFalse(isNotDir);

    }

    @Test
    public void testCheckHomeParam() {
        String good_zap_home = "C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy\\";
        String bad_zap_home = "C:\\Program Files (x86)";
        String good_acunetix_home = "C:\\Program Files (x86)\\Acunetix\\Web Vulnerability Scanner 9\\";
        boolean isGoodZap = ConfigurationUtils.checkHomeParam(ScannerType.ZAPROXY, good_zap_home);
        boolean isBadZap = ConfigurationUtils.checkHomeParam(ScannerType.ZAPROXY, bad_zap_home);
        boolean isGoodAcunetix = ConfigurationUtils.checkHomeParam(ScannerType.ACUNETIX_WVS, good_acunetix_home);

        Assert.assertTrue(isGoodZap);
        Assert.assertFalse(isBadZap);
        Assert.assertTrue(isGoodAcunetix);
    }

//    @Test
//    public void testConfigScannerType() {
//        ConfigurationUtils.configScannerType(ScannerType.ZAPROXY, config);
//        Assert.assertNotNull(config.getString("zap.scanName"));
//        Assert.assertNotNull(config.getString("zap.scanVersion"));
//        Assert.assertNotNull(config.getString("zap.scanExecutablePath"));
//        Assert.assertNotNull(config.getString("zap.scanHost"));
//        Assert.assertNotNull(config.getString("zap.scanPort"));
//    }
//
//    @Test
//    public void testConfigSystemInfo() {
//        ConfigurationUtils.configSystemInfo(config);
//        Assert.assertNotNull(config.getString("scanagent.threadFixServerUrl"));
//        Assert.assertNotNull(config.getString("scanagent.threadFixApiKey"));
//        Assert.assertNotNull(config.getString("scanagent.baseWorkDir"));
//    }

    @Test
    public void testGetPropertiesFile() {
        Assert.assertNotNull(ConfigurationUtils.getPropertiesFile());
    }

}
