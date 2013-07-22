package com.denimgroup.threadfix.service.framework;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class DefaultTranslator extends AbstractPathUrlTranslator {

	private final SanitizedLogger log = new SanitizedLogger("DefaultTranslator");

	public DefaultTranslator(ScanMergeConfiguration scanMergeConfiguration,
			Scan scan) {
		super(scanMergeConfiguration, scan);

		filePathRoot = findOrParseProjectRoot(scan);
		urlPathRoot = findOrParseUrlPath(scan);
		scan.setFilePathRoot(filePathRoot);
		scan.setUrlPathRoot(urlPathRoot);
		
		log.info("Using default URL - Path translator.");
		log.info("Calculated filesystem root: " + filePathRoot);
		log.info("Calculated url path root: " + urlPathRoot);
	}

	@Override
	public String getFileName(Finding finding) {
		return getFileNameDefault(finding);
	}

	@Override
	public String getUrlPath(Finding finding) {
		return getUrlPathDefault(finding);
	}
	
}
