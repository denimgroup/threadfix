package com.denimgroup.threadfix.service.framework;

import java.io.File;

import com.denimgroup.threadfix.data.entities.Finding;

public class DefaultURLCalculator extends AbstractURLCalculator {

	public DefaultURLCalculator(ServletMappings mappings, File workTree,
			String applicationRoot) {
		super(mappings, workTree, applicationRoot);
	}

	@Override
	public boolean findMatch(Finding finding) {
		return false;
	}

}
