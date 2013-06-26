package com.denimgroup.threadfix.service.framework;

import java.io.File;

import org.eclipse.jgit.lib.Repository;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.service.repository.GitService;

public class URLCalculatorFactory {
	
	private static final String baseDirectory = "C:\\test\\scratch\\";

	// TODO add more appropriate field to Application object
	// the reason for not doing it now is that 1.2 changes will be easier to absorb if we wait
	public static AbstractURLCalculator getAppropriateCalculator(Application application) {
		if (application == null || application.getUrl() == null) {
			return null;
		}
		
		File applicationDirectory = new File(baseDirectory + application.getId());
		
		Repository repo = GitService.cloneGitTreeToDirectory(application.getUrl(), applicationDirectory);
		
		if (repo != null && repo.getWorkTree() != null && repo.getWorkTree().exists()) {
			File webXML = new ProjectDirectory(repo.getWorkTree()).findWebXML();
			if (webXML != null && webXML.exists()) {
				ServletMappings mappings = WebXMLParser.getServletMappings(webXML);
				
				if (mappings != null) {
					switch (mappings.guessApplicationType()) {
						case JSP:
							return new JSPURLCalculator(mappings, repo.getWorkTree());
						case SERVLET:
							return new ServletURLCalculator(mappings, repo.getWorkTree());
						case SPRING:
							return new SpringURLCalculator(mappings, repo.getWorkTree());
					}
				}
			}
		}
		
		return null;
	}
	
}
