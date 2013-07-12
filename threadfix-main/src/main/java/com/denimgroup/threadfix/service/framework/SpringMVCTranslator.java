package com.denimgroup.threadfix.service.framework;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class SpringMVCTranslator extends AbstractPathUrlTranslator {

	public SpringMVCTranslator(ScanMergeConfiguration scanMergeConfiguration) {
		super(scanMergeConfiguration);
	}

	@Override
	public boolean findMatch(Finding finding) {
		log.warn("Spring's unimplemented findMatch method was called.");
		// TODO Auto-generated method stub
		return false;
	}
	
}
