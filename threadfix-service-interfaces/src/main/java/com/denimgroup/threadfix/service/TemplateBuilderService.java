package com.denimgroup.threadfix.service;

import java.util.Map;

public interface TemplateBuilderService {

	public String prepareMessageFromTemplate(Map<String,Object> model, String templateName);
}
