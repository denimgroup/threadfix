package com.denimgroup.threadfix.service.framework;

import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class PathUrlTranslatorFactory {
	
	// TODO add more appropriate field to Application object
	// the reason for not doing it now is that 1.2 changes will be easier to absorb if we wait
	public static PathUrlTranslator getTranslator(ScanMergeConfiguration scanMergeConfiguration, 
			Scan scan) {
		switch (scanMergeConfiguration.getFrameworkType()) {
			case SPRING_MVC: 
				return new SpringMVCTranslator(scanMergeConfiguration, scan);
			case JSP: 
				return new JSPTranslator(scanMergeConfiguration, scan);
			default: 
				return new DefaultTranslator(scanMergeConfiguration, scan);
		}
	}
}
