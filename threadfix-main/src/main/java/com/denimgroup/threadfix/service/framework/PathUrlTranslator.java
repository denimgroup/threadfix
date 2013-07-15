package com.denimgroup.threadfix.service.framework;

import com.denimgroup.threadfix.data.entities.Finding;

public interface PathUrlTranslator {
	
	String getFileName(Finding finding);
	
	String getUrlPath(Finding finding);
}
