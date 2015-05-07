package com.denimgroup.threadfix.service;

import java.util.Map;

public interface EmailBuilderService {

	public String prepareMessageFromTemplate(Map<String,Object> model, String templateName);
}
