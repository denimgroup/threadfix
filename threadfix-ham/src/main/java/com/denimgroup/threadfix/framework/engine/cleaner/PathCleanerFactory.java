package com.denimgroup.threadfix.framework.engine.cleaner;

import java.util.List;

import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.impl.jsp.JSPPathCleaner;
import com.denimgroup.threadfix.framework.impl.spring.SpringPathCleaner;
import org.jetbrains.annotations.NotNull;

public class PathCleanerFactory {
	
	private PathCleanerFactory(){}
	
	// TODO add an option for manual roots
	
	@NotNull
    public static PathCleaner getPathCleaner(FrameworkType frameworkType, List<PartialMapping> partialMappings) {
		PathCleaner returnCleaner;
		
		if (frameworkType == FrameworkType.SPRING_MVC) {
			returnCleaner = new SpringPathCleaner(partialMappings);
        } else if (frameworkType == FrameworkType.JSP) {
            returnCleaner = new JSPPathCleaner(partialMappings);
		} else {
			returnCleaner = new DefaultPathCleaner(partialMappings);
		}
		
		return returnCleaner;
	}

}
