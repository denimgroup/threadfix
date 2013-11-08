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

import java.io.File;
import java.util.List;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import com.denimgroup.threadfix.framework.impl.jsp.JSPMappings;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

// TODO incorporate include parsing
public class JSPTranslator extends AbstractPathUrlTranslator {
	
	private final SanitizedLogger log = new SanitizedLogger("JSPTranslator");
	
	private final JSPMappings mappings;
	
	public JSPTranslator(ScanMergeConfiguration scanMergeConfiguration,
			Scan scan) {
		super(scanMergeConfiguration, scan);
		
		if (scan == null || !scan.isStatic()) {
			filePathRoot = CommonPathFinder.findOrParseProjectRootFromDirectory(
					scanMergeConfiguration.getWorkTree(),
					".jsp");
		} else {
			filePathRoot = CommonPathFinder.findOrParseProjectRoot(scan.toPartialMappingList(), ".jsp");
		}
		urlPathRoot  = CommonPathFinder.findOrParseUrlPath(scan.toPartialMappingList());
		
		if (filePathRoot != null) {
			mappings = new JSPMappings(new File(filePathRoot));
		} else {
			mappings = new JSPMappings(null);
		}

		if ((urlPathRoot == null || urlPathRoot.isEmpty()) && filePathRoot != null) {
			urlPathRoot = filePathRoot;
		}
		
		if (scan != null) {
			scan.setFilePathRoot(filePathRoot);
			scan.setUrlPathRoot(urlPathRoot);
		}
		
		log.info("Using JSP URL - Path translator.");
		log.info("Calculated filesystem root: " + filePathRoot);
		log.info("Calculated url path root: " + urlPathRoot);
	}

	@Override
	public String getFileName(Finding finding) {
		switch (scanMergeConfiguration.getSourceCodeAccessLevel()) {
			case FULL: return getFileNameWithSourceCode(finding);
			default:   return getFileNameDefault(finding);
		}
	}

	private String getFileNameWithSourceCode(Finding finding) {
		String fileName = super.getFileNameWithSourceCodeDefault(finding);
		
		if (finding != null && finding.getSurfaceLocation() != null) {
			finding.setEntryPointLineNumber(
				mappings.getFirstLineNumber(
				fileName, finding.getSurfaceLocation().getParameter()));
		
		}
		
		return fileName;
	}
	
	@Override
	public String getUrlPath(Finding finding) {
		return getUrlPathDefault(finding);
	}

	@Override
	public List<Endpoint> generateEndpoints() {
		return mappings.generateEndpoints();
	}
	
}
