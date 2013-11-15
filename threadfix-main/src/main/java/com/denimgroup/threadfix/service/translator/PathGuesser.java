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
package com.denimgroup.threadfix.service.translator;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParser;
import com.denimgroup.threadfix.framework.engine.parameter.ParameterParserFactory;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

// TODO convert to use EndpointDatabase and get rid of the PathUrlTranslator
public class PathGuesser {
	
	private PathGuesser(){}
	
	public static void generateGuesses2(Application application, Scan scan) {
		if (scan == null || scan.getFindings() == null || scan.getFindings().isEmpty()) {
			return;
		}
		
		FindingProcessor processor = FindingProcessorFactory.getProcessor(application, scan);
		
		calculateLocations2(scan, processor);
	}

	private static void calculateLocations2(Scan scan, FindingProcessor processor) {
		
		for (Finding finding : scan.getFindings()) {
			if (finding != null) {
				processor.process(finding);
			}
		}
	}
	
	public static void generateGuesses(ScanMergeConfiguration scanMergeConfiguration, Scan scan) {
		if (scan == null || scan.getFindings() == null || scan.getFindings().isEmpty()) {
			return;
		}
		
		ParameterParser parser = ParameterParserFactory.getParameterParser(scanMergeConfiguration);
		
		PathUrlTranslator translator = PathUrlTranslatorFactory.getTranslator(scanMergeConfiguration, scan);
		
		calculateLocations(scan, translator, parser);
	}

	private static void calculateLocations(Scan scan, PathUrlTranslator translator,
			ParameterParser parser) {
		
		for (Finding finding : scan.getFindings()) {
			if (finding != null) {
				finding.setCalculatedFilePath(translator.getFileName(finding));
				finding.setCalculatedUrlPath(translator.getUrlPath(finding));
				if (parser != null && finding.getSurfaceLocation() != null) {
					finding.getSurfaceLocation().setParameter(parser.parse(finding.toEndpointQuery()));
				}
			}
		}
	}
}
