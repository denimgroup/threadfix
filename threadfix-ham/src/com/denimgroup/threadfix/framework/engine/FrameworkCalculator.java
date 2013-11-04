package com.denimgroup.threadfix.framework.engine;

import java.io.File;

import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.util.SanitizedLogger;

// TODO make this more generic
public class FrameworkCalculator {
	
	private FrameworkCalculator(){}
	
	private static final SanitizedLogger log = new SanitizedLogger("MergeConfigurationGenerator");
	
	public static FrameworkType getType(File rootFile) {
		log.info("Attempting to guess Framework Type from source tree.");
		log.info("File: " + rootFile);
		
		FrameworkType frameworkType = FrameworkType.NONE;
		
		if (rootFile != null && rootFile.exists() && rootFile.isDirectory()) {
			ProjectDirectory projectDirectory = new ProjectDirectory(rootFile);
			
			File webXML = projectDirectory.findWebXML();
			if (webXML != null && webXML.exists()) {
				ServletMappings mappings = WebXMLParser.getServletMappings(webXML, projectDirectory);
				
				if (mappings != null) {
					frameworkType = mappings.guessApplicationType();
				}
			}
		}
		
		log.info("Source tree framework type detection returned: " + frameworkType.getDisplayName());
		
		return frameworkType;
	}

}
