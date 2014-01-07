package com.denimgroup.threadfix.framework.engine.framework;

import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import org.jetbrains.annotations.NotNull;

import java.io.File;

public class WebXmlFrameworkChecker extends FrameworkChecker {

    @NotNull
    @Override
    public FrameworkType check(@NotNull ProjectDirectory directory) {
        FrameworkType frameworkType = FrameworkType.NONE;

        File webXML = directory.findWebXML();
        if (webXML != null && webXML.exists()) {
            ServletMappings mappings = WebXMLParser.getServletMappings(webXML, directory);

            if (mappings != null) {
                frameworkType = mappings.guessApplicationType();
            }
        }

        return frameworkType;
    }
}
