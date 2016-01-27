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

import com.denimgroup.threadfix.data.dao.DefectTrackerDao;
import com.denimgroup.threadfix.data.entities.DefaultDefectField;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

@Service
public class DefaultDefectFieldServiceImpl implements DefaultDefectFieldService {

	private static final SanitizedLogger LOG = new SanitizedLogger(DefaultDefectFieldServiceImpl.class);
	private static final char TAG_WILDWARD = '@';

	@Autowired
	private DefaultTagMappingService tagMappingService;
	@Autowired
	private DefectTrackerDao defectTrackerDao;
	@Autowired
	private SessionFactory sessionFactory;

	@Override
	public String getDefaultValueForVulns(DefaultDefectField defaultDefectField, List<Vulnerability> vulnerabilities) {
		if (!defaultDefectField.isDynamicDefault()) return defaultDefectField.getStaticValue();
		else {
			String findingValueForTag = null;
			if (defaultDefectField.getDefaultTag() != null)
				findingValueForTag = tagMappingService.evaluateTagValueForVulns(defaultDefectField.getDefaultTag(), vulnerabilities);
			else { // instead of hardcore only one default tag for each DefaultDefectField, now we can be flexible by substituting @tag in dynamic values
				findingValueForTag = tagMappingService.evaluateTagValueForVulnsFromPattern(defaultDefectField.getDynamicValue(), vulnerabilities);
			}
			if (!defaultDefectField.isValueMapping()) return findingValueForTag;
			else {
				Map<String, String> valueMappingMap = defaultDefectField.getValueMappingMap();
				if (!valueMappingMap.containsKey(findingValueForTag)) return null;
				else return valueMappingMap.get(findingValueForTag);
			}
		}
	}

	@Override
	public List<DefaultDefectField> parseDefaultDefectsFields(String newDefaultsJson) {
		ObjectMapper mapper = new ObjectMapper();
		List<DefaultDefectField> newDefaultFields = list();
		try {
			JsonNode defectDefaultsTree = mapper.readTree(newDefaultsJson);
			Iterator<Entry<String, JsonNode>> fields = defectDefaultsTree.getFields();
			while(fields.hasNext()){
				Entry<String, JsonNode> field = fields.next();
				String fieldName = field.getKey();
				JsonNode fieldValue = field.getValue();

				DefaultDefectField parsedDefaultDefectField = parseDefaultField(fieldValue);
				if (parsedDefaultDefectField != null){
					parsedDefaultDefectField.setFieldName(fieldName);
					newDefaultFields.add(parsedDefaultDefectField);
				}
			}
			return newDefaultFields;

		} catch (JsonProcessingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	private DefaultDefectField parseDefaultField(JsonNode valueNode){
		if (valueNode.isTextual()){
			//parse not value mapping field
			return parseNormalDefaultField(valueNode.getTextValue());
		}
		else if (valueNode.isObject()){
			//parse valueMapping field
			return parseValueMappingDefaultField(valueNode);
		}
		else {
			//value type is not supported, boolean or number are not ignored yet
			return null;
		}
	}

	private DefaultDefectField parseNormalDefaultField(String defaultValue){
		if (defaultValue.length() == 0) return null;

		DefaultDefectField parsedDefaultDefectField = new DefaultDefectField();
		parsedDefaultDefectField.setValueMapping(false);

		if (defaultValue.indexOf(TAG_WILDWARD) != -1) {
			parsedDefaultDefectField.setDynamicDefault(true);
			parsedDefaultDefectField.setDynamicValue(defaultValue);
		}
		else{
			parsedDefaultDefectField.setDynamicDefault(false);
			parsedDefaultDefectField.setStaticValue(defaultValue);;
		}
		return parsedDefaultDefectField;
	}

	private DefaultDefectField parseValueMappingDefaultField(JsonNode valueMappingNode){
		try {
			String tagName = valueMappingNode.get("tagName").getTextValue(); //will cause null pointer exception if protocol is not respected
			JsonNode valueMapping = valueMappingNode.get("valueMapping");
			String staticTagDisplayValue = valueMappingNode.get("staticDisplayValue").getTextValue(); // to maintain original form inputted

			if (!tagMappingService.nameExists(tagName)) return null;

			DefaultDefectField parsedDefaultDefectField = new DefaultDefectField();
			parsedDefaultDefectField.setDefaultTag(tagMappingService.loadByName(tagName));
			parsedDefaultDefectField.setValueMapping(true);
			parsedDefaultDefectField.setDynamicDefault(true);
			parsedDefaultDefectField.setStaticValue(staticTagDisplayValue);

			List<String> validKeys = tagMappingService.getTagKeysOrNull(tagName);
			Map<String,String> valueMappingMap = map();

			Iterator<String> keys = valueMapping.getFieldNames();
			while(keys.hasNext()){
				String key = keys.next();
				String value = valueMapping.get(key).getTextValue();
				if (validKeys.contains(key) && value != null){
					valueMappingMap.put(key, value);
				}
			}
			parsedDefaultDefectField.setValueMappingMap(valueMappingMap);
			return parsedDefaultDefectField;

		} catch (NullPointerException e) {
			LOG.info("deserialization failed for a non compliant DefectDefaultField, skipping it", e);
		}
		return null;
	}

}
