////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.jetbrains.annotations.NotNull;

// TODO make this more generic
public class FrameworkCalculator {
	
	private FrameworkCalculator(){}
	
	private static final SanitizedLogger log = new SanitizedLogger("FrameworkCalculator");

    private Collection<FrameworkChecker> frameworkCheckers = new ArrayList<>();

    private static FrameworkCalculator INSTANCE = new FrameworkCalculator();

    static {
        // TODO detect language first and use that to narrow down the frameworks
        // TODO incorporate python code
        // TODO add .NET code
        register(new JavaAndJspFrameworkChecker());
    }

    public static void register(FrameworkChecker checker) {
        INSTANCE.frameworkCheckers.add(checker);
    }
	
	@NotNull
    public static FrameworkType getType(@NotNull File rootFile) {
		log.info("Attempting to guess Framework Type from source tree.");
		log.info("File: " + rootFile);
		
		FrameworkType frameworkType = FrameworkType.NONE;
		
		if (rootFile.exists() && rootFile.isDirectory()) {
            ProjectDirectory projectDirectory = new ProjectDirectory(rootFile);

            for (FrameworkChecker checker : INSTANCE.frameworkCheckers) {
                frameworkType = checker.check(projectDirectory);
                if (frameworkType != FrameworkType.NONE) {
                    break;
                }
            }
		}
		
		log.info("Source tree framework type detection returned: " + frameworkType.getDisplayName());
		
		return frameworkType;
	}

}
