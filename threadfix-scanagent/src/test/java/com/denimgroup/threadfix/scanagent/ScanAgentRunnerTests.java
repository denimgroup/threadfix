package com.denimgroup.threadfix.scanagent;

import com.denimgroup.threadfix.scanagent.stub.StubThreadFixRestClient;
import com.denimgroup.threadfix.scanagent.util.ConfigurationUtils;
import junit.framework.TestCase;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.jetbrains.annotations.Nullable;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/20/13
 * Time: 11:24 AM
 * To change this template use File | Settings | File Templates.
 */
public class ScanAgentRunnerTests extends TestCase {
    @Nullable
    private static PropertiesConfiguration config = ConfigurationUtils.getPropertiesFile();

    public static final String RETURN_NULL_URL = "nullUrl";
    public static final String RETURN_ERROR_URL = "errorUrl";
    public static final String RETURN_GOOD_URL = "goodUrl";
    private static final String REAL_URL = "http://localhost:8080/threadfix/rest";
    private static final int maxTasks = 2;

    @Before
    public void setUp() {
        // Make sure there's at least one scanner setup
        config.setProperty("zap.scanName", "OWASP Zed Attack Proxy");
        config.setProperty("zap.scanVersion", "2.2.2");
        config.setProperty("zap.scanExecutablePath", "C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy\\");
        config.setProperty("zap.scanHost", "localhost");
        config.setProperty("zap.scanPort", "8090");
    }

    @After
    public void tearDown() {
        config.setProperty("scanagent.threadFixServerUrl", REAL_URL);
        config.setProperty("scanagent.maxTasks", 1);
    }

    @Test
    public void testRun1() {
        config.setProperty("scanagent.threadFixServerUrl", RETURN_NULL_URL);
        config.setProperty("scanagent.maxTasks", maxTasks);
        ScanAgentRunner runner = new ScanAgentRunner();
        runner.setTfClient(new StubThreadFixRestClient());
        runner.run();

        Assert.assertEquals(maxTasks, runner.getNumTasksAttempted());
    }

    @Test
    public void testRun2() {
        config.setProperty("scanagent.threadFixServerUrl", RETURN_ERROR_URL);
        config.setProperty("scanagent.maxTasks", maxTasks);
        ScanAgentRunner runner = new ScanAgentRunner();
        runner.setTfClient(new StubThreadFixRestClient());
        runner.run();

        Assert.assertEquals(maxTasks, runner.getNumTasksAttempted());
    }

    @Test
    public void testRun3() {
        config.setProperty("scanagent.threadFixServerUrl", RETURN_GOOD_URL);
        config.setProperty("scanagent.maxTasks", maxTasks);
        ScanAgentRunner runner = new ScanAgentRunner();
        runner.setTfClient(new StubThreadFixRestClient());
        runner.run();

        Assert.assertEquals(maxTasks, runner.getNumTasksAttempted());
    }


}
