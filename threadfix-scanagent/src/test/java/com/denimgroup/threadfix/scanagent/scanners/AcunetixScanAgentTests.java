package com.denimgroup.threadfix.scanagent.scanners;

import com.denimgroup.threadfix.data.entities.TaskConfig;
import com.denimgroup.threadfix.scanagent.stub.StubThreadFixRestClient;
import junit.framework.TestCase;
import org.jetbrains.annotations.Nullable;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/20/13
 * Time: 2:19 PM
 * To change this template use File | Settings | File Templates.
 */
public class AcunetixScanAgentTests extends TestCase {

    private static final String ACUNETIX_HOME = "C:\\Program Files (x86)\\Acunetix\\Web Vulnerability Scanner 9\\";
    private static final String WORK_DIR = "C:\\Users\\stran\\Desktop\\ScanAgentUnitTest";
    private static final String BAD_ACUNETIX_HOME = "C:\\Program Files (x86)\\Acunetix\\";
    @Nullable
    private AcunetixScanAgent agent;

    @Before
    public void setUp() {
        Scanner scanner = new Scanner();
        scanner.setHomeDir(ACUNETIX_HOME);
        agent = AcunetixScanAgent.getInstance(scanner, WORK_DIR);
        agent.setTfClient(new StubThreadFixRestClient());

        //Make sure delete export file
        try{
            File file = new File(WORK_DIR + File.separator + "export.xml");
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
        TaskConfig taskConfig = null;
        try {
            taskConfig = new TaskConfig(new URL("http://localhost:8086/bodgeit1234/"));
            File file = agent.doTask(taskConfig);
            Assert.assertNotNull(file);
        } catch (MalformedURLException e) {
            Assert.fail();
        }

    }

    @Test
    public void testDoTask3() {
        try {
            TaskConfig taskConfig = new TaskConfig(new URL("http://localhost:8086/bodgeit/"));
            File file = agent.doTask(taskConfig);
            agent.setAcunetixExecutablePath(BAD_ACUNETIX_HOME);
            Assert.assertNotNull(file);
        } catch (MalformedURLException e) {
            Assert.fail();
        }
    }
}
