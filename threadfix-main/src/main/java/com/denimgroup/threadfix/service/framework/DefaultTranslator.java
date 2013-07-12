package com.denimgroup.threadfix.service.framework;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class DefaultTranslator extends AbstractPathUrlTranslator {

	public DefaultTranslator(ScanMergeConfiguration scanMergeConfiguration) {
		super(scanMergeConfiguration);
	}

	@Override
	public boolean findMatch(Finding finding) {
		return false;
	}

}
