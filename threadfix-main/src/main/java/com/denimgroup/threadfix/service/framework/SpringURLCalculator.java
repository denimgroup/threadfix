package com.denimgroup.threadfix.service.framework;

import java.io.File;

import com.denimgroup.threadfix.data.entities.Finding;

public class SpringURLCalculator extends AbstractURLCalculator {

	public SpringURLCalculator(ServletMappings mappings, File workTree,
			String applicationRoot) {
		super(mappings, workTree, applicationRoot);
	}

	@Override
	public boolean findMatch(Finding finding) {
		log.warn("Spring's unimplemented findMatch method was called.");
		// TODO Auto-generated method stub
		return false;
	}
	
}
