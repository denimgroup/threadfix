////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.impl.rails;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkChecker;
import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.*;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.FileFilter;
import java.util.Collection;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by sgerick on 5/7/2015.
 */
public class RailsFrameworkChecker extends FrameworkChecker {

    private static final SanitizedLogger LOG = new SanitizedLogger(RailsFrameworkChecker.class);

    private boolean routesFound = false;
    private static final String ROUTES_RB = "routes.rb";
    private static final String ROUTE_DIR = "config";

    @Nonnull
    @Override
    public FrameworkType check(@Nonnull ProjectDirectory directory) {

        Collection<File> rbFiles = FileUtils.listFiles(directory.getDirectory(),
                new FileExtensionFileFilter("rb"), TrueFileFilter.TRUE);

        for (File rbFile : rbFiles) {
            if (rbFile.getPath().toLowerCase().endsWith(ROUTES_RB)
                    && rbFile.getPath().toLowerCase().contains(ROUTE_DIR)) {
                routesFound = true;
                break;
            }
        }

        LOG.info("Got " + rbFiles.size() + " *.rb files from the directory.");
        LOG.info(".../" + ROUTE_DIR + "/" + ROUTES_RB + " was " + (routesFound ? "" : "NOT ") + "found.");

        return !routesFound ? FrameworkType.NONE : FrameworkType.RAILS;
    }

//    public static void main(String[] args) {
//        RailsFrameworkChecker railsFrameworkChecker = new RailsFrameworkChecker();
//        File file = new File("C:\\SourceCode\\railsgoat-master");
//        ProjectDirectory projectDirectory = new ProjectDirectory(file);
//        FrameworkType frameworkType = railsFrameworkChecker.check(projectDirectory);
//        LOG.info("FrameworkType is " + frameworkType.getDisplayName());
//    }
}
