package com.denimgroup.threadfix.service.framework;

import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class PathUrlTranslatorFactory {
	
	// TODO add more appropriate field to Application object
	// the reason for not doing it now is that 1.2 changes will be easier to absorb if we wait
	public static PathUrlTranslator getTranslator(ScanMergeConfiguration scanMergeConfiguration) {
		switch (scanMergeConfiguration.getFrameworkType()) {
			case SPRING_MVC: 
				return new SpringMVCTranslator(scanMergeConfiguration);
			case JSP: 
				return new JSPTranslator(scanMergeConfiguration);
			default: 
				return new DefaultTranslator(scanMergeConfiguration);
		}
	}
}
