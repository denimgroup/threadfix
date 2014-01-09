package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

import java.io.File;

import static junit.framework.Assert.assertTrue;

/**
 * Created by mac on 1/7/14.
 */
public class SpringJavaConfigurationCheckerTests {

    @Test
    public void testAnnotationsOnly() {
        File file = ResourceManager.getSpringFile("config/MyConfiguration.java");
        assertTrue("Annotations only failed.", SpringJavaConfigurationChecker.checkJavaFile(file));
    }

    @Test
    public void testAnnotationsAndClass() {
        File file = ResourceManager.getSpringFile("config/MyWebConfiguration.java");
        assertTrue("WebMvcConfigurerAdapter subclass failed.", SpringJavaConfigurationChecker.checkJavaFile(file));
    }

    @Test
    public void testClassOnly() {
        File file = ResourceManager.getSpringFile("config/MyConfiguration.java");
        assertTrue("WebMvcConfigurationSupport subclass failed.", SpringJavaConfigurationChecker.checkJavaFile(file));
    }

    @Test
    public void testWithAnnotations() {
        File file = ResourceManager.getSpringFile("config/ConfigWithCurlyInAnnotation.java");
        assertTrue("Failed to parse with curly braces in annotations.",
                SpringJavaConfigurationChecker.checkJavaFile(file));
    }

}
