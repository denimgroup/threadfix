package com.denimgroup.threadfix.service.framework;

import java.io.File;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public abstract class AbstractPathUrlTranslator implements PathUrlTranslator {

	protected final ServletMappings mappings;
	protected final File workTree;
	protected final String applicationRoot;
	protected final ScanMergeConfiguration scanMergeConfiguration;
	
	protected final SanitizedLogger log = new SanitizedLogger(this.getClass());
	
	/**
	 * Throws IllegalArgumentException if passed null parameters.
	 * @param mappings
	 * @param workTree
	 */
	public AbstractPathUrlTranslator(ScanMergeConfiguration configuration) {
		
		this.mappings = configuration.getServletMappings();
		this.workTree = configuration.getWorkTree();
		this.applicationRoot = "/" + configuration.getApplicationRoot();
		this.scanMergeConfiguration = configuration;
		
		if (!this.workTree.exists()) {
			log.warn("File doesn't exist.");
		}
	}

	public void findMatches(Scan scan) {
		if (scan == null || scan.getFindings() == null || scan.getFindings().size() == 0) {
			return;
		}
		
		int success = 0, failure = 0;
		
		for (Finding finding : scan.getFindings()) {
			if (findMatch(finding)) {
				success ++;
			} else {
				failure ++;
			}
		}
		
		System.out.println("Total     : " + (success + failure));
		System.out.println("Success   : " + (success));
		System.out.println("Percentage: " + (100.0 * success) / (success + failure));
	}
	
	public abstract boolean findMatch(Finding finding);
	
}
