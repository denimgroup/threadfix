package com.denimgroup.threadfix.service.merge;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.framework.PathUrlTranslator;
import com.denimgroup.threadfix.service.framework.PathUrlTranslatorFactory;

public class PathGuesser {
	
	private PathGuesser(){}
	
	public static void generateGuesses(ScanMergeConfiguration scanMergeConfiguration, Scan scan) {
		
		PathUrlTranslator translator = PathUrlTranslatorFactory.getTranslator(scanMergeConfiguration, scan);
		calculateLocations(scan, translator);
	}
	
	private static void calculateLocations(Scan scan, PathUrlTranslator translator) {
		if (scan == null || scan.getFindings() == null || scan.getFindings().isEmpty()) {
			return;
		}
		
		for (Finding finding : scan.getFindings()) {
			if (finding != null) {
				finding.setCalculatedFilePath(translator.getFileName(finding));
				finding.setCalculatedUrlPath(translator.getUrlPath(finding));
			}
		}
	}
}
