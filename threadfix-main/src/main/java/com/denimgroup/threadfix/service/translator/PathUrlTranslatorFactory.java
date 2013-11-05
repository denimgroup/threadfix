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

import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.merge.ScanMergeConfiguration;

public class PathUrlTranslatorFactory {
	
	// TODO add more appropriate field to Application object
	// the reason for not doing it now is that 1.2 changes will be easier to absorb if we wait
	public static PathUrlTranslator getTranslator(ScanMergeConfiguration scanMergeConfiguration, 
			Scan scan) {
		switch (scanMergeConfiguration.getFrameworkType()) {
			case SPRING_MVC: 
				return new SpringMVCTranslator(scanMergeConfiguration, scan);
			case JSP: 
				return new JSPTranslator(scanMergeConfiguration, scan);
			default: 
				return new DefaultTranslator(scanMergeConfiguration, scan);
		}
	}
}
