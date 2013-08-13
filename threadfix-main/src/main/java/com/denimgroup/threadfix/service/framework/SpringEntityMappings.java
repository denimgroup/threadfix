package com.denimgroup.threadfix.service.framework;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;


public class SpringEntityMappings {

private final Collection<File> modelFiles;
	
	private final Map<String, BeanFieldSet> fieldMap;
	
	@SuppressWarnings("unchecked")
	public SpringEntityMappings(File rootDirectory) {
		if (rootDirectory != null && rootDirectory.exists()) {
			modelFiles = FileUtils.listFiles(rootDirectory, 
					SpringEntityFileFilter.INSTANCE, TrueFileFilter.INSTANCE);
		
			fieldMap = new HashMap<>();
			
			if (modelFiles != null) {
				generateMap();
			}
		} else {
			modelFiles = null;
			fieldMap = new HashMap<>();
		}
	}
	
	public BeanFieldSet getFieldsForModel(String className) {
		BeanFieldSet fields = fieldMap.get(className);
		
		if (fields == null) {
			fields = new BeanFieldSet(new HashSet<BeanField>());
		}
		
		return fields;
	}
	
	public List<BeanField> getFieldsFromMethodCalls(String methodCalls, BeanField initialField) {
		List<BeanField> fields = new ArrayList<>();
		
	
		if (methodCalls != null && initialField != null) {
			fields.add(initialField);
			
			BeanField currentField = initialField;
			String editedCalls = methodCalls;
			
			if (methodCalls.startsWith(initialField.getParameterKey())) {
				editedCalls = methodCalls.substring(initialField.getParameterKey().length());
			}
			
			String[] calls = editedCalls.split("(\\(\\))");
			
			for (String call : calls) {
				if (call != null && ! call.isEmpty()) {
					String beanAccessor = getParameterFromBeanAccessor(call);
					if (fieldMap.containsKey(currentField.getType()) &&
							fieldMap.get(currentField.getType()).contains(beanAccessor)) {
						BeanField resultField = fieldMap.get(currentField.getType()).getField(beanAccessor);
						if (resultField != null && !resultField.equals(currentField)) {
							fields.add(resultField);
							currentField = resultField;
						}
					} else {
						break;
					}
				}
			}
		}
		
		return fields;
	}
	
	public boolean isEmpty() {
		return fieldMap.isEmpty();
	}

	private void generateMap() {
		if (modelFiles == null) {
			return;
		}
		
		Map<String, String> superClassMap = new HashMap<>();
		
		addModelsToSuperClassAndFieldMaps(superClassMap);
		
		addSuperClassFieldsToModels(superClassMap);
	}
	
	private void addSuperClassFieldsToModels(Map<String, String> superClassMap) {
		Set<String> done = new HashSet<>();
		
		for (String key : fieldMap.keySet()) {
			if (!superClassMap.containsKey(key)) {
				done.add(key);
			}
		}
		
		// we need to do it this way in case we miss some class in the hierarchy and can't resolve
		// all of the superclasses
		int lastSize = 0;
		
		while (superClassMap.size() != lastSize) {
			lastSize = superClassMap.size();
			for (String key : superClassMap.keySet()) {
				if (done.contains(superClassMap.get(key))) {
					fieldMap.get(key).addAll(fieldMap.get(superClassMap.get(key)));
					done.add(key);
				}
			}
			superClassMap.keySet().removeAll(done);
		}
	}

	private void addModelsToSuperClassAndFieldMaps(Map<String, String> superClassMap) {
		for (File file: modelFiles) {
			if (file != null && file.exists() && file.isFile()) {
				
				SpringEntityParser entityParser = SpringEntityParser.parse(file);
				
				if (entityParser.getClassName() != null && entityParser.getFieldMappings() != null) {
					
					if (entityParser.getSuperClass() != null) {
						superClassMap.put(entityParser.getClassName(), entityParser.getSuperClass());
					}
					
					fieldMap.put(entityParser.getClassName(), new BeanFieldSet(entityParser.getFieldMappings()));
				}
			}
		}
	}
	
	private String getParameterFromBeanAccessor(String methodCall) {
		
		String propertyName = null;
		
		if (methodCall.startsWith(".get")) {
			propertyName = methodCall.substring(4);
			propertyName = propertyName.substring(0,1).toLowerCase() + propertyName.substring(1);
		}
		
		return propertyName;
	}
	
}
