package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertTrue;

/**
 * Created by mac on 1/6/14.
 */
public class SpringDetectionTests {

    @Test
    public void petclinicTest() {
        testTypeDetection(TestConstants.PETCLINIC_SOURCE_LOCATION);
    }

    @Test
    public void testMvcAjaxConfig() {
        testTypeDetection(TestConstants.getFolderName("spring-mvc-ajax"));
    }

    @Test
    public void testMvcExamplesConfig() {
        testTypeDetection(TestConstants.getFolderName("spring-mvc-examples"));
    }

    @Test
    public void testMvcShowcaseConfig() {
        testTypeDetection(TestConstants.getFolderName("spring-mvc-showcase"));
    }

    @Test
    public void testMvcChatConfig() {
        testTypeDetection(TestConstants.getFolderName("spring-mvc-chat"));
    }

    void testTypeDetection(String location) {
        FrameworkType type = FrameworkCalculator.getType(new File(location));
        assertTrue("Didn't find Spring. Got: " + type, type == FrameworkType.SPRING_MVC);
    }

}
