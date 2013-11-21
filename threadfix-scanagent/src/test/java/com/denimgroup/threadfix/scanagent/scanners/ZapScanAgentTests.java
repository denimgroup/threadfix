package com.denimgroup.threadfix.scanagent.scanners;

import com.denimgroup.threadfix.data.entities.TaskConfig;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import com.denimgroup.threadfix.scanagent.stub.StubThreadFixRestClient;
import junit.framework.TestCase;
import org.jetbrains.annotations.Nullable;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/20/13
 * Time: 4:10 PM
 * To change this template use File | Settings | File Templates.
 */
public class ZapScanAgentTests extends TestCase {

    private static final String ZAP_HOME = "C:\\Program Files (x86)\\OWASP\\Zed Attack Proxy\\";
    private static final String WORK_DIR = "C:\\Users\\stran\\Desktop\\ScanAgentUnitTest";
    private static final String BAD_ZAP_HOME = "C:\\Program Files (x86)\\OWASP\\";
    @Nullable
    private ZapScanAgent agent;

    @Before
    public void setUp() {
        Scanner scanner = new Scanner();
        scanner.setHomeDir(ZAP_HOME);
        scanner.setHost("localhost");
        scanner.setPort(8090);
        agent = ZapScanAgent.getInstance(scanner, WORK_DIR);
        agent.setTfClient(new StubThreadFixRestClient());

        //Make sure delete export file
        try{
            File file = new File(WORK_DIR + File.separator + "ZAPRESULTS.xml");
            if(file.exists() && file.delete()){
                System.out.println(file.getName() + " is deleted!");
            }else{
                System.out.println("Delete operation is failed.");
            }
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    // Make sure http://localhost:8086/bodgeit/ running
    @Test
    public void testDoTask1() {
        try {
            TaskConfig taskConfig = new TaskConfig(new URL("http://localhost:8086/bodgeit/"));
            File file = agent.doTask(taskConfig);
            Assert.assertNotNull(file);
        } catch (MalformedURLException e) {
            Assert.fail();
        }
    }

    @Test
    public void testDoTask2() {
        try {
            TaskConfig taskConfig = new TaskConfig(new URL("http://localhost:8086/bodgeit12344/"));
            File file = agent.doTask(taskConfig);
            Assert.assertNull(file);
        } catch (MalformedURLException e) {
            Assert.fail();
        }
    }

    @Test
    public void testDoTask3() {
        try {
            TaskConfig taskConfig = new TaskConfig(new URL("http://localhost:8086/bodgeit/"));
            agent.setZapExecutablePath(BAD_ZAP_HOME);
            File file = agent.doTask(taskConfig);
            Assert.assertNull(file);
        } catch (MalformedURLException e) {
            Assert.fail();
        }
    }
}
