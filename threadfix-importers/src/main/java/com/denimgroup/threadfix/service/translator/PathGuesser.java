////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import com.denimgroup.threadfix.logging.SanitizedLogger;

public class PathGuesser {
	
	private PathGuesser(){}

    private static final SanitizedLogger LOG = new SanitizedLogger(PathGuesser.class);

    public static void generateGuesses(Application application, Scan scan) {
        if (scan == null || scan.getFindings() == null || scan.getFindings().isEmpty()) {
            LOG.error("Unable to generate guesses because the scan was null or empty.");
            return;
        }

        LOG.info("Starting HAM-based url and file path calculations.");

        FindingProcessor processor = FindingProcessorFactory.getProcessor(application, scan);

        calculateLocations(scan, processor);
    }

    private static void calculateLocations(Scan scan, FindingProcessor processor) {

        for (Finding finding : scan.getFindings()) {
            if (finding != null) {
                processor.process(finding);
            }
        }

        processor.printStatistics();
    }
}
