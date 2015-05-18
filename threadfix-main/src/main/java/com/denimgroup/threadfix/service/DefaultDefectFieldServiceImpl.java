package com.denimgroup.threadfix.service;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.list;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.DefectTrackerDao;
import com.denimgroup.threadfix.data.entities.DefaultDefectField;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.logging.SanitizedLogger;

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
			String findingValueForTag = tagMappingService.evaluateTagValueForVulns(defaultDefectField.getDefaultTag(), vulnerabilities);
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

		if (defaultValue.charAt(0) == TAG_WILDWARD){
			String tagName = defaultValue.substring(1);
			if (!tagMappingService.nameExists(tagName)) return null;
			else {
				parsedDefaultDefectField.setDynamicDefault(true);
				parsedDefaultDefectField.setDefaultTag(tagMappingService.loadByName(tagName));
			}
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

			if (!tagMappingService.nameExists(tagName)) return null;

			DefaultDefectField parsedDefaultDefectField = new DefaultDefectField();
			parsedDefaultDefectField.setDefaultTag(tagMappingService.loadByName(tagName));
			parsedDefaultDefectField.setValueMapping(true);
			parsedDefaultDefectField.setDynamicDefault(true);

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
