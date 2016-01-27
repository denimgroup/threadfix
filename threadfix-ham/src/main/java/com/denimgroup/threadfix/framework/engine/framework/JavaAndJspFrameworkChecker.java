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

package com.denimgroup.threadfix.framework.engine.framework;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.framework.impl.spring.SpringJavaConfigurationChecker;
import com.denimgroup.threadfix.framework.impl.struts.StrutsConfigurationChecker;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import javax.annotation.Nonnull;

import java.io.File;
import java.util.Collection;
import java.util.Iterator;

public class JavaAndJspFrameworkChecker extends FrameworkChecker {

    @Nonnull
    @Override
    @SuppressWarnings("unchecked")
    public FrameworkType check(@Nonnull ProjectDirectory directory) {

        FrameworkType frameworkType = FrameworkType.NONE;

        File webXML = directory.findWebXML();
        if (webXML != null && webXML.exists()) {
            ServletMappings mappings = WebXMLParser.getServletMappings(webXML, directory);

            if (mappings != null) {
                frameworkType = mappings.guessApplicationType();
            }
        }

        if (frameworkType == FrameworkType.SPRING_MVC)
            return frameworkType;

        // check for STRUTS
        Collection<File> configFiles = FileUtils.listFiles(directory.getDirectory(), new String[]{"xml", "properties"}, true);
        if (StrutsConfigurationChecker.check(configFiles)) {
            frameworkType = FrameworkType.STRUTS;
            return frameworkType;
        }


        // check for SPRING
        Collection<File> javaFiles = FileUtils.listFiles(directory.getDirectory(),
                new FileExtensionFileFilter("java"), TrueFileFilter.INSTANCE);

        for (File file : javaFiles) {
            if (SpringJavaConfigurationChecker.checkJavaFile(file)) {
                frameworkType = FrameworkType.SPRING_MVC;
                break;
            }
        }

        return frameworkType;
    }
}
