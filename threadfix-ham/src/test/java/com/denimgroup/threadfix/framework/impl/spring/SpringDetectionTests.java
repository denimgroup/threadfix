package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.TestConstants;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertTrue;

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

    public static final String[] ALL_SPRING_APPS = {
            "atmosphere-spring-mvc",
            "blog",
            "blog-spring",
            "BookExchange",
            "classifiedsMVC",
            "CRM_Demo",
            "denarius",
            "documentmanager",
            "dogphone-spring-mongo",
            "EchoWeb",
            "exhubs",
            "mvc-calculator",
            "MvcXmlFree",
            "spring-guestbook",
            "spring-mvc-ajax",
            "spring-mvc-chat",
            "spring-mvc-examples",
            "spring-mvc-inventory",
            "spring-mvc-movies",
            "spring-mvc-scribe-experiment",
            "spring-mvc-showcase",
            "spring-mvc-with-no-xml-experiment",
            "spring-wiki",
            "spring3-mvc-cities",
            "SpringUserAuthSample",
            "stonewall",
            "ticketline-spring",
            "Timeline",
            "todomvc",
            "WebCalculator",
            "woofer" };

    @Test
    public void testTheOtherWebapps() {
        for (String app : ALL_SPRING_APPS) {
            testTypeDetection(TestConstants.getFolderName("spring/" + app));
        }
    }

    void testTypeDetection(String location) {
        FrameworkType type = FrameworkCalculator.getType(new File(location));
        assertTrue("Didn't find Spring in " + location + ". Got: " + type, type == FrameworkType.SPRING_MVC);
    }

}
