////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.DefaultTagDao;
import com.denimgroup.threadfix.data.dao.GenericNamedObjectDao;
import com.denimgroup.threadfix.data.entities.DefaultTag;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.framework.util.RegexUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.defaults.AbstractDefaultTagMapper;
import com.denimgroup.threadfix.service.defects.defaults.DefaultTagMapperFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

@Service
public class DefaultTagMappingServiceImpl extends AbstractNamedObjectService<DefaultTag> implements DefaultTagMappingService {

	private static final SanitizedLogger LOG = new SanitizedLogger(DefaultTagMappingServiceImpl.class);

	@Autowired
	private DefaultTagDao defaultTagDao;
	@Autowired
	private DefaultTagMapperFactory defaultTagMapperFactory;

	@Override
	public String evaluateTagValueForVulns(DefaultTag tag, List<Vulnerability> vulnerabilities) {
		AbstractDefaultTagMapper tagMapper = defaultTagMapperFactory.getTagMapperFromDefaultTag(tag);
		return tagMapper.getValueAssociated(vulnerabilities);
	}

	@Override
	public List<Object> getTagsWithValueMappingFields() {
		List<Object> tagsWithValueMappingFields = list();
		List<DefaultTag> defaultTags = defaultTagDao.retrieveAll();

		for (DefaultTag tag : defaultTags) {
			Map<String,Object> tagWithFields = map("name", (Object) tag.getName(), "description", (Object) tag.getDescription());
			AbstractDefaultTagMapper tagMapper = defaultTagMapperFactory.getTagMapperFromDefaultTag(tag);
			if(tagMapper.isSupportingValueMapping()){
				tagWithFields.put("valueMapping", true);
				tagWithFields.put("valueMappingFields", tagMapper.getValueMappingKeys());
			}
			else {
				tagWithFields.put("valueMapping", false);
			}
			tagsWithValueMappingFields.add(tagWithFields);
		}
		return tagsWithValueMappingFields;
	}

	@Override
	public List<String> getTagKeysOrNull(String tagName){ //for the moment we assume that tagName is verified before calling this function
		DefaultTag tag = defaultTagDao.retrieveByName(tagName);
		if (tag == null) return null;

		AbstractDefaultTagMapper tagMapper = defaultTagMapperFactory.getTagMapperFromDefaultTag(tag);
		LOG.debug("tagMapper loaded");
		if (tagMapper.isSupportingValueMapping()){
			return tagMapper.getValueMappingKeys();
		}
		else {
			return null;
		}
	}

	@Override
	public String evaluateTagValueForVulnsFromPattern(String dynamicPattern, List<Vulnerability> vulnerabilities) {
		List<String> tagStrList = RegexUtils.getRegexResults(dynamicPattern, Pattern.compile("@([\\S]+)"));
		for (String tagStr: tagStrList) {
			if (nameExists(tagStr)) {
				String tagValue = evaluateTagValueForVulns(loadByName(tagStr), vulnerabilities);
				dynamicPattern = dynamicPattern.replaceFirst("@" + tagStr, tagValue);
			}
		}
		return dynamicPattern;
	}

	@Override
	public GenericNamedObjectDao<DefaultTag> getDao() {
		return defaultTagDao;
	}

}
