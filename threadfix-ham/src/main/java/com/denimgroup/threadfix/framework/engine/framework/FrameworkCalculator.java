package com.denimgroup.threadfix.framework.engine.framework;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import org.jetbrains.annotations.NotNull;

import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.util.SanitizedLogger;

// TODO make this more generic
public class FrameworkCalculator {
	
	private FrameworkCalculator(){}
	
	private static final SanitizedLogger log = new SanitizedLogger("FrameworkCalculator");

    private Set<FrameworkChecker> frameworkCheckers = new HashSet<>();

    private static FrameworkCalculator INSTANCE = new FrameworkCalculator();

    static {
        register(new WebXmlFrameworkChecker());
        register(new SpringJavaFrameworkChecker());
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
