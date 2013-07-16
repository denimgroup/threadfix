package com.denimgroup.threadfix.service.framework;

import java.io.File;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class JSPTranslator extends AbstractPathUrlTranslator {
	
	// TODO figure out the best way to get the application root into this class
	// I'm guessing it'll be in the Application
	
	private final ProjectDirectory projectDirectory;
	private final File aboveWebInf;

	public JSPTranslator(ScanMergeConfiguration scanMergeConfiguration, Scan scan) {
		super(scanMergeConfiguration, scan);
		log.info("Using JSP URL - Path translator.");
		
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

	// What this really does is find a matching file on the filesystem.
	public boolean findMatch(Finding finding) {
		
		if (finding == null || aboveWebInf == null || !aboveWebInf.isDirectory()) {
			return false;
		}
		
		String topDirectory = aboveWebInf.getName();
		
		boolean match = false;
		
		if (finding.getDataFlowElements() == null || 
				finding.getDataFlowElements().isEmpty()) {
			
		} else {

			// Attempt static matching
			for (DataFlowElement element : finding.getDataFlowElements()) {
				if (element != null && element.getSourceFileName() != null) {
					String elementPath = element.getSourceFileName();
					if (elementPath.contains(topDirectory)) {

						String strippedPath = elementPath.substring(elementPath
								.indexOf(topDirectory) + topDirectory.length());

						if (finding.getSurfaceLocation() != null) {
							finding.getSurfaceLocation().setPath(strippedPath);
						}

						System.out.println("stripped path = " + strippedPath);

						String pathAttempt = aboveWebInf.getAbsolutePath()
								+ strippedPath;

						if (new File(pathAttempt).exists()) {
							System.out.println("located file at " + pathAttempt);
						} else {
							System.out.println("unable to locate file at "
									+ pathAttempt);
						}
					}
				}
			}
		}
		
		return match;
	}

	@Override
	public String getFileName(Finding dynamicFinding) {
		String sourcePath = null;
		if (dynamicFinding != null && !dynamicFinding.getIsStatic() &&
				dynamicFinding.getSurfaceLocation() != null &&
				dynamicFinding.getSurfaceLocation().getPath() != null) {
			
			String path = dynamicFinding.getSurfaceLocation().getPath();
			
			switch (scanMergeConfiguration.getSourceCodeAccessLevel()) {
				case FULL:    sourcePath = guessSourcePathWithSourceCode(path); break;
				case PARTIAL: sourcePath = guessSourcePathWithDataFlows(path);  break;
				default:      sourcePath = guessSourcePathWithNoSource(path);   break;
			}
			// TODO implement backwards dynamic path -> static file location matching
		}
		return sourcePath;
	}

	// TODO Figure out what other information we need for this method
	private String guessSourcePathWithNoSource(String path) {
		return path;
	}

	// TODO figure out what other information we need for this method
	private String guessSourcePathWithDataFlows(String path) {
		return path;
	}

	// TODO improve by figuring out the root on the filesystem so we can generate the path from the root
	private String guessSourcePathWithSourceCode(String path) {
		return path;
	}

	@Override
	public String getUrlPath(Finding staticFinding) {
		String returnPath = null;
		if (staticFinding != null && staticFinding.getIsStatic() &&
				staticFinding.getDataFlowElements() != null && 
				!staticFinding.getDataFlowElements().isEmpty()) {
			
			switch (scanMergeConfiguration.getSourceCodeAccessLevel()) {
				case FULL:    returnPath = guessUrlPathWithSourceCode(staticFinding); break;
				case PARTIAL: returnPath = guessUrlPathWithDataFlows(staticFinding);  break;
				default:      returnPath = guessUrlPathWithNoSource(staticFinding);   break;
			}
			// TODO implement backwards dynamic path -> static file location matching
		}
		return returnPath;
	}
	
	// TODO Figure out what other information we need for this method
	private String guessUrlPathWithNoSource(Finding finding) {
		return null;
	}

	// TODO figure out what other information we need for this method
	private String guessUrlPathWithDataFlows(Finding finding) {
		return null;
	}

	// TODO improve by figuring out the root on the filesystem so we can generate the path from the root
	private String guessUrlPathWithSourceCode(Finding finding) {
		if (finding == null || aboveWebInf == null || !aboveWebInf.isDirectory()) {
			return null;
		}
		
		return null;
	}
}
