////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.framework.engine.cleaner;

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.impl.dotNetWebForm.WebFormsPathCleaner;
import com.denimgroup.threadfix.framework.impl.jsp.JSPPathCleaner;
import com.denimgroup.threadfix.framework.impl.spring.SpringPathCleaner;

import javax.annotation.Nonnull;
import java.util.List;

public class PathCleanerFactory {
	
	private PathCleanerFactory(){}
	
	// TODO add an option for manual roots
	
	@Nonnull
    public static PathCleaner getPathCleaner(FrameworkType frameworkType, List<PartialMapping> partialMappings) {
		PathCleaner returnCleaner;
		
		if (frameworkType == FrameworkType.SPRING_MVC) {
			returnCleaner = new SpringPathCleaner(partialMappings);
        } else if (frameworkType == FrameworkType.JSP) {
            returnCleaner = new JSPPathCleaner(partialMappings);
        } else if (frameworkType == FrameworkType.DOT_NET_WEB_FORMS) {
            returnCleaner = new WebFormsPathCleaner(partialMappings);
		} else {
			returnCleaner = new DefaultPathCleaner(partialMappings);
		}
		
		return returnCleaner;
	}

}
