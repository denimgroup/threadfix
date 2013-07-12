package com.denimgroup.threadfix.service.framework;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class PathUrlTranslatorFactory {
	
	
	
	// TODO add more appropriate field to Application object
	// the reason for not doing it now is that 1.2 changes will be easier to absorb if we wait
	public static AbstractPathUrlTranslator getTranslator(Application application) {
		if (application == null || application.getUrl() == null) {
			return null;
		}
		
		ScanMergeConfiguration configuration = MergeConfigurationGenerator.generateConfiguration(application);
		
		switch (configuration.getFrameworkType()) {
			case SPRING_MVC: 
				return new SpringMVCTranslator(configuration);
			case JSP: 
				return new JSPTranslator(configuration);
			default: 
				return new DefaultTranslator(configuration);
		}
	}

}
