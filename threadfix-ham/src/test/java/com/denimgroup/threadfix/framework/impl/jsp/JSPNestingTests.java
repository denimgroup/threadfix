package com.denimgroup.threadfix.framework.impl.jsp;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class JSPNestingTests {

    @Test
    public void test7LevelNesting() {
        JSPMappings mappings = new JSPMappings(ResourceManager.getFile("code.jsp/nesting"));

        for (Endpoint endpoint : mappings) {
            assertTrue("param1 was missing from " + endpoint.getFilePath(),
                    endpoint.getParameters().contains("param1"));
        }
    }

    // this should throw StackOverflowException if cycles aren't recognized properly
    @Test
    public void testCycle() {
        JSPMappings mappings = new JSPMappings(ResourceManager.getFile("code.jsp.cycle"));

        for (Endpoint endpoint : mappings) {
            assertTrue("param1 was missing from " + endpoint.getFilePath(),
                    endpoint.getParameters().contains("test"));
        }
    }

}
