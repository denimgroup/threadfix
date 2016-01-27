////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.ResourceManager;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertTrue;

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
