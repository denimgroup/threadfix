package com.denimgroup.threadfix.service.framework;

import java.io.File;

import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public abstract class AbstractPathUrlTranslator implements PathUrlTranslator {

	protected final ServletMappings mappings;
	protected final File workTree;
	protected final String applicationRoot;
	protected final ScanMergeConfiguration scanMergeConfiguration;
	protected final Scan scan;
	
	protected final SanitizedLogger log = new SanitizedLogger(this.getClass());
	
	/**
	 * Throws IllegalArgumentException if passed null parameters.
	 * @param scan 
	 * @param mappings
	 * @param workTree
	 */
	public AbstractPathUrlTranslator(ScanMergeConfiguration configuration, Scan scan) {
		
		this.mappings = configuration.getServletMappings();
		this.workTree = configuration.getWorkTree();
		this.applicationRoot = "/" + configuration.getApplicationRoot();
		this.scanMergeConfiguration = configuration;
		this.scan = scan;
		
		if (this.workTree == null || !this.workTree.exists()) {
			log.warn("Work tree doesn't exist.");
		}
	}
}
