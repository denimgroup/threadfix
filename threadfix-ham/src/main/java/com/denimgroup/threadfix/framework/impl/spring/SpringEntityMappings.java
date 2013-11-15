////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.impl.spring;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.util.*;

class SpringEntityMappings {

	@NotNull
    private final Collection<File> modelFiles;
	
	@NotNull
    private final Map<String, BeanFieldSet> fieldMap;
	
	@SuppressWarnings("unchecked")
	public SpringEntityMappings(@NotNull File rootDirectory) {
        fieldMap = new HashMap<>();

		if (rootDirectory.exists() && rootDirectory.isDirectory()) {
			modelFiles = FileUtils.listFiles(rootDirectory,
					SpringEntityFileFilter.INSTANCE, TrueFileFilter.INSTANCE);
		
            generateMap();
		} else {
			modelFiles = Collections.emptyList();
		}
	}
	
	public BeanFieldSet getPossibleParametersForModelType(@NotNull BeanField beanField) {
		return getPossibleParametersForModelType(beanField.getType());
	}
	
	/**
	 * This method uses recursion to walk the tree of possible parameters that the spring
	 * controller will accept and bind to the model object. This information should be
	 * added in addition to all of the normal parameters (@RequestMapping, @PathVariable)
	 */
	public BeanFieldSet getPossibleParametersForModelType(String className) {
		BeanFieldSet fields = fieldMap.get(className);
		
		if (fields == null) {
			fields = new BeanFieldSet(new HashSet<BeanField>());
		}
		
		Set<String> alreadyVisited = new HashSet<>();
		alreadyVisited.add(className);
		
		BeanFieldSet fieldsToAdd = new BeanFieldSet(new HashSet<BeanField>());
		
		for (BeanField field : fields) {
			if (fieldMap.containsKey(field.getType()) && !alreadyVisited.contains(field.getType())) {
				alreadyVisited.add(field.getType());
				fieldsToAdd.addAll(spiderFields(field.getParameterKey() + ".", field.getType(), alreadyVisited));
			}
		}
		
		return fields.addAll(fieldsToAdd);
	}
	
	@NotNull
    private BeanFieldSet spiderFields(String prefix, String className, @NotNull Set<String> alreadyVisited) {
		BeanFieldSet fields = fieldMap.get(className);
		
		if (fields == null) {
			fields = new BeanFieldSet(new HashSet<BeanField>());
		}
		
		BeanFieldSet
			fieldsToAdd = new BeanFieldSet(new HashSet<BeanField>()),
			fieldsWithPrefixes = new BeanFieldSet(new HashSet<BeanField>());
		
		for (BeanField field : fields) {
			if (fieldMap.containsKey(field.getType()) && !alreadyVisited.contains(field.getType())) {
				alreadyVisited.add(field.getType());
				fieldsToAdd.addAll(spiderFields(field.getParameterKey() + ".", field.getType(), alreadyVisited));
			}
		}
		
		for (BeanField field : fieldsToAdd.addAll(fields)) {
			fieldsWithPrefixes.add(new BeanField(field.getType(), prefix + field.getParameterKey()));
		}
		
		return fieldsWithPrefixes;
	}
	
	@NotNull
    public List<BeanField> getFieldsFromMethodCalls(@Nullable String methodCalls, @Nullable BeanField initialField) {
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
		Map<String, String> superClassMap = new HashMap<>();
		
		addModelsToSuperClassAndFieldMaps(superClassMap);
		
		addSuperClassFieldsToModels(superClassMap);
	}
	
	private void addSuperClassFieldsToModels(@NotNull Map<String, String> superClassMap) {
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

	private void addModelsToSuperClassAndFieldMaps(@NotNull Map<String, String> superClassMap) {
		for (File file: modelFiles) {
			if (file != null && file.exists() && file.isFile()) {
				
				SpringEntityParser entityParser = SpringEntityParser.parse(file);
				
				if (entityParser.getClassName() != null) {
					
					if (entityParser.getSuperClass() != null) {
						superClassMap.put(entityParser.getClassName(), entityParser.getSuperClass());
					}
					
					fieldMap.put(entityParser.getClassName(), new BeanFieldSet(entityParser.getFieldMappings()));
				}
			}
		}
	}
	
	@Nullable
    private String getParameterFromBeanAccessor(@NotNull String methodCall) {
		
		String propertyName = null;
		
		if (methodCall.startsWith(".get")) {
			propertyName = methodCall.substring(4);
			propertyName = propertyName.substring(0,1).toLowerCase() + propertyName.substring(1);
		}
		
		return propertyName;
	}
	
	@Override
	public String toString() {
		return fieldMap.toString();
	}
	
}
