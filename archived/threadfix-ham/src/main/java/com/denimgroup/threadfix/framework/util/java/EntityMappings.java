////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.util.java;

import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.framework.impl.model.FieldSetLookupUtils;
import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.impl.model.ModelFieldSet;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.io.File;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.framework.impl.model.FieldSetLookupUtils.addSuperClassFieldsToModels;

public class EntityMappings {

    // This should be done by the end of the constructor
    @Nonnull
    private final Collection<EntityParser> entityParsers;

    @Nonnull
    private final Map<String, ModelFieldSet> fieldMap = map();

    // This version will parse all the Java files in the directory.
    @SuppressWarnings("unchecked")
    public EntityMappings(@Nonnull File rootDirectory) {

        entityParsers = list();

        if (rootDirectory.exists() && rootDirectory.isDirectory()) {

            Collection<File> modelFiles = FileUtils.listFiles(rootDirectory,
                    new FileExtensionFileFilter("java"), TrueFileFilter.TRUE);

            for (File file : modelFiles) {
                if (file != null && file.exists() && file.isFile()) {
                    entityParsers.add(EntityParser.parse(file));
                }
            }

            generateMap();
        }
    }

    public EntityMappings(@Nonnull Collection<EntityParser> entityParsers) {
        this.entityParsers = entityParsers;
        generateMap();
    }

    public ModelFieldSet getPossibleParametersForModelType(@Nonnull ModelField beanField) {
        return getPossibleParametersForModelType(beanField.getType());
    }

    /**
     * This method uses recursion to walk the tree of possible parameters that the spring
     * controller will accept and bind to the model object. This information should be
     * added in addition to all of the normal parameters (@RequestMapping, @PathVariable)
     */
    public ModelFieldSet getPossibleParametersForModelType(String className) {
        return FieldSetLookupUtils.getPossibleParametersForModelType(fieldMap, className);
	}
	
	@Nonnull
    public List<ModelField> getFieldsFromMethodCalls(@Nullable String methodCalls, @Nullable ModelField initialField) {
		List<ModelField> fields = list();

		if (methodCalls != null && initialField != null) {
			fields.add(initialField);
			
			ModelField currentField = initialField;
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
						ModelField resultField = fieldMap.get(currentField.getType()).getField(beanAccessor);
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
		Map<String, String> superClassMap = map();
		
		addModelsToSuperClassAndFieldMaps(superClassMap);
		
		addSuperClassFieldsToModels(fieldMap, superClassMap);
	}

    private void addModelsToSuperClassAndFieldMaps(@Nonnull Map<String, String> superClassMap) {
        for (EntityParser entityParser : entityParsers) {

            if (entityParser.getClassName() != null) {

                if (entityParser.getSuperClass() != null) {
                    superClassMap.put(entityParser.getClassName(), entityParser.getSuperClass());
                }

                fieldMap.put(entityParser.getClassName(), new ModelFieldSet(entityParser.getFieldMappings()));
            }
        }
    }
	
	@Nullable
    private String getParameterFromBeanAccessor(@Nonnull String methodCall) {
		
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
