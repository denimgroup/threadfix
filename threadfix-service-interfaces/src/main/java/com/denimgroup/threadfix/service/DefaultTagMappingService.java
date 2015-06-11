package com.denimgroup.threadfix.service;

import java.util.List;
import com.denimgroup.threadfix.data.entities.DefaultTag;
import com.denimgroup.threadfix.data.entities.Vulnerability;

public interface DefaultTagMappingService extends GenericNamedObjectService<DefaultTag> {

	public String evaluateTagValueForVulns(DefaultTag tag, List<Vulnerability> vulnerabilities);

	/**
	 * This function is meant to be compliant with the protocol for listing the available tags 
	 * and return a map that can just be integrated in larger object before serialization
	 * 
	 */
	public List<Object> getTagsWithValueMappingFields();

	public List<String> getTagKeysOrNull(String tagName);

	String evaluateTagValueForVulnsFromPattern(String dynamicPattern, List<Vulnerability> vulnerabilities);
}
