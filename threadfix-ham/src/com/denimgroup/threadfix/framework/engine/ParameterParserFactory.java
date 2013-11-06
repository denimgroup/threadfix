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
package com.denimgroup.threadfix.framework.engine;

import com.denimgroup.threadfix.framework.beans.ParameterParser;
import com.denimgroup.threadfix.framework.impl.jsp.JSPDataFlowParser;
import com.denimgroup.threadfix.framework.impl.jsp.JSPMappings;
import com.denimgroup.threadfix.framework.impl.spring.SpringDataFlowParser;
import com.denimgroup.threadfix.framework.impl.spring.SpringEntityMappings;

public class ParameterParserFactory {
	
	public static ParameterParser getParameterParser(ProjectConfig projectConfig) {
		ParameterParser parser = null;
		
		if (projectConfig.getFrameworkType()!= null) {
			switch (projectConfig.getFrameworkType()) {
				case SPRING_MVC:
					SpringEntityMappings mappings = null;
					if (projectConfig.getRootFile() != null) {
						mappings = new SpringEntityMappings(projectConfig.getRootFile());
					}
					parser = new SpringDataFlowParser(mappings);
					
					break;
				case JSP:
					JSPMappings jspMappings = null;
					if (projectConfig.getRootFile() != null) {
						jspMappings = new JSPMappings(projectConfig.getRootFile());
					}
					parser = new JSPDataFlowParser(jspMappings, projectConfig.getSourceCodeAccessLevel());
					
					break;
				default:
			}
		}
		
		return parser;
	}
}
