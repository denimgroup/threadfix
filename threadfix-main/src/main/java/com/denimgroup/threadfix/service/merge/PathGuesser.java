////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.merge;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.framework.ParameterParser;
import com.denimgroup.threadfix.service.framework.ParameterParserFactory;
import com.denimgroup.threadfix.service.framework.PathUrlTranslator;
import com.denimgroup.threadfix.service.framework.PathUrlTranslatorFactory;

public class PathGuesser {
	
	private PathGuesser(){}
	
	public static void generateGuesses(ScanMergeConfiguration scanMergeConfiguration, Scan scan) {
		
		PathUrlTranslator translator = PathUrlTranslatorFactory.getTranslator(scanMergeConfiguration, scan);
		ParameterParser   parser     = ParameterParserFactory.getParameterParser(scanMergeConfiguration);
		
		calculateLocations(scan, translator, parser);
	}
	
	private static void calculateLocations(Scan scan, PathUrlTranslator translator, 
			ParameterParser parser) {
		if (scan == null || scan.getFindings() == null || scan.getFindings().isEmpty()) {
			return;
		}
		
		for (Finding finding : scan.getFindings()) {
			if (finding != null) {
				finding.setCalculatedFilePath(translator.getFileName(finding));
				finding.setCalculatedUrlPath(translator.getUrlPath(finding));
				if (parser != null && finding.getSurfaceLocation() != null) {
					finding.getSurfaceLocation().setParameter(parser.parse(finding));
				}
			}
		}
	}
}
