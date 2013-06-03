package com.denimgroup.threadfix.service.framework;

import java.io.File;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;

public class JSPURLCalculator extends AbstractURLCalculator {
	
	// TODO figure out the best way to get the application root into this class
	// I'm guessing it'll be in the Application
	String applicationRoot = "/wavsep";
	
	private ProjectDirectory projectDirectory = null;
	private File aboveWebInf = null;

	public JSPURLCalculator(ServletMappings mappings, File workTree) {
		super(mappings, workTree);
		projectDirectory = new ProjectDirectory(workTree);
		aboveWebInf = findDirectoryAboveWebInf();
	}
	
	public File findDirectoryAboveWebInf() {
		
		File aboveWebInf = null;
		
		if (workTree != null && workTree.exists() && workTree.isDirectory()) {
			File webXML = projectDirectory.findWebXML();
			if (webXML != null && webXML.exists()) {
				File webInf = webXML.getParentFile();
				if (webXML != null && webXML.exists()) {
					aboveWebInf = webInf.getParentFile();
				}
			}
		}
		
		return aboveWebInf;
	}

	@Override
	public boolean findMatch(Finding finding) {
		
		if (finding == null || aboveWebInf == null || !aboveWebInf.isDirectory()) {
			return false;
		}
		
		String topDirectory = aboveWebInf.getName();
		
		boolean match = false;
		
		if (finding.getDataFlowElements() == null || 
				finding.getDataFlowElements().isEmpty()) {
			
			// Attempt dynamic matching
			if (finding.getSurfaceLocation() != null && finding.getSurfaceLocation().getPath() != null &&
					finding.getSurfaceLocation().getPath().contains(applicationRoot)) {
				String path = finding.getSurfaceLocation().getPath();
				finding.getSurfaceLocation().setPath(path.substring(path.indexOf(applicationRoot)));
				match = true;
			}
			
		} else {
			
			// Attempt static matching
			for (DataFlowElement element : finding.getDataFlowElements()) {
				if (element != null && element.getSourceFileName() != null) {
					String elementPath = element.getSourceFileName();
					if (elementPath.contains(topDirectory)) {
						
						String strippedPath = elementPath.substring(elementPath.indexOf(topDirectory) + topDirectory.length());
						
						if (finding.getSurfaceLocation() != null) {
							finding.getSurfaceLocation().setPath(applicationRoot + strippedPath);
						}
						
						
						System.out.println("stripped path = " + strippedPath);
						
						String pathAttempt = aboveWebInf.getAbsolutePath() + strippedPath;
						
						if (new File(pathAttempt).exists()) {
							System.out.println("located file at " + pathAttempt);
							match = true;
						} else {
							System.out.println("unable to locate file at " + pathAttempt);
						}
					}
				}
			}
		}
		
		return match;
	}
	
//		boolean match = false;
//		
//		for (DataFlowElement element : finding.getDataFlowElements()) {
//			if (element != null && element.getSourceFileName() != null) {
//				File result = projectDirectory.findFile(
//						getClassName(element.getSourceFileName()), "java", "src", "main");
//						
//				if (result != null) {
//					match = true;
//					System.out.println(".");
//					System.out.println(element.getSourceFileName() + " ("
//							+ getClassName(element.getSourceFileName()) + " -> " + result.getAbsolutePath());
//				} else {
//					System.out.println(",");
//				}
//			}
//		}
//		
//		return match;
//	}
	
//	private String getClassName(String input) {
//		String returnName = input;
//		
//		if (returnName.contains("\\")) {
//			returnName = returnName.replace('\\', '/');
//		}
//		
//		returnName = returnName.replace('/', '.');
//		if (returnName.contains("java")) {
//			returnName = returnName.substring(returnName.indexOf("java") + 4);
//		}
//		
//		if (returnName.charAt(0) == '.') {
//			returnName = returnName.substring(1);
//		}
//		
//		if (returnName.endsWith(".jsp")) {
//			returnName = returnName.substring(0, returnName.length() - 4);
//		}
//		
//		while (returnName.indexOf('.') != -1) {
//			returnName = returnName.substring(returnName.indexOf('.') + 1);
//		}
//		
//		return returnName;
//	}

}
