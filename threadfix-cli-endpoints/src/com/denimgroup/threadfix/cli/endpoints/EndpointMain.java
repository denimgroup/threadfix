package com.denimgroup.threadfix.cli.endpoints;

import java.io.File;
import java.util.List;

import com.denimgroup.threadfix.service.framework.Endpoint;
import com.denimgroup.threadfix.service.framework.PathUrlTranslator;
import com.denimgroup.threadfix.service.framework.PathUrlTranslatorFactory;
import com.denimgroup.threadfix.service.merge.FrameworkType;
import com.denimgroup.threadfix.service.merge.MergeConfigurationGenerator;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;
import com.denimgroup.threadfix.service.merge.SourceCodeAccessLevel;
import com.denimgroup.threadfix.service.merge.VulnTypeStrategy;

public class EndpointMain {
	
	public static void main(String[] args) {
		if (args.length != 1) {
			System.out.println("This program takes 1 argument, the file root.");
			
		} else {
		
			File rootFile = new File(args[0]);
			
			if (!rootFile.exists()) {
				System.out.println("The root file didn't exist.");
			} else {
				listEndpoints(rootFile);
			}
		}
	}
	
	private static void listEndpoints(File rootFile) {
		
		FrameworkType type = MergeConfigurationGenerator.guessFrameworkTypeFromSourceTree(rootFile);
		
		if (type == FrameworkType.NONE) {
			System.out.println("No framework found. Make sure that the file is the root " +
					"of a JSP or Spring MVC project and try again.");
		} else {
		
			System.out.println("Type was " + type);
		
			ScanMergeConfiguration configuration = new ScanMergeConfiguration(
					VulnTypeStrategy.EXACT,
					SourceCodeAccessLevel.FULL,
					type,
					rootFile,
					null, 
					null);
			
			PathUrlTranslator translator = PathUrlTranslatorFactory.getTranslator(configuration, null);
			
			List<Endpoint> endpoints = translator.generateEndpoints();
			
			if (endpoints.isEmpty()) {
				System.out.println("No endpoints were found.");
			} else {
				for (Endpoint endpoint : endpoints) {
					System.out.println(endpoint.getCSVLine());
				}
			}
		}
	}

}
