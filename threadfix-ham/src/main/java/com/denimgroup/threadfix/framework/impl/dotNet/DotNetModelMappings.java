////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.impl.model.ModelFieldSet;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.util.*;

/**
 * Created by mac on 8/27/14.
 */
public class DotNetModelMappings {

    // This should be done by the end of the constructor
    @Nonnull
    private final Collection<ViewModelParser> modelParsers;

    @Nonnull
    private final Map<String, ModelFieldSet> fieldMap = new HashMap<>();

    // This version will parse all the Java files in the directory.
    @SuppressWarnings("unchecked")
    public DotNetModelMappings(@Nonnull File rootDirectory) {

        modelParsers = new ArrayList<>();

        if (rootDirectory.exists() && rootDirectory.isDirectory()) {

            Collection<File> modelFiles = FileUtils.listFiles(rootDirectory,
                    new FileExtensionFileFilter("cs"), TrueFileFilter.INSTANCE);

            for (File file : modelFiles) {
                if (file != null && file.exists() && file.isFile()) {
                    modelParsers.add(ViewModelParser.parse(file));
                }
            }
        }

        collapse();
    }

    public DotNetModelMappings(@Nonnull Collection<ViewModelParser> modelParsers) {
        this.modelParsers = modelParsers;
        collapse();
    }

    public ModelFieldSet getPossibleParametersForModelType(@Nonnull ModelField beanField) {
        return getPossibleParametersForModelType(beanField.getType());
    }

    private void collapse() {
        for (ViewModelParser parser : modelParsers) {
            for (Map.Entry<String, Set<ModelField>> entry : parser.map.entrySet()) {
                fieldMap.put(entry.getKey(), new ModelFieldSet(entry.getValue()));
            }
        }
    }

    /**
     * This method uses recursion to walk the tree of possible parameters that the spring
     * controller will accept and bind to the model object. This information should be
     * added in addition to all of the normal parameters (@RequestMapping, @PathVariable)
     */
    public ModelFieldSet getPossibleParametersForModelType(String className) {
        ModelFieldSet fields = fieldMap.get(className);

        if (fields == null) {
            fields = new ModelFieldSet(new HashSet<ModelField>());
        }

        Set<String> alreadyVisited = new HashSet<>();
        alreadyVisited.add(className);

        ModelFieldSet fieldsToAdd = new ModelFieldSet(new HashSet<ModelField>());

        for (ModelField field : fields) {
            if (fieldMap.containsKey(field.getType()) && !alreadyVisited.contains(field.getType())) {
                alreadyVisited.add(field.getType());
                fieldsToAdd.addAll(spiderFields(field.getParameterKey() + ".", field.getType(), alreadyVisited));
            }
        }

        return fields.addAll(fieldsToAdd);
    }

    @Nonnull
    private ModelFieldSet spiderFields(String prefix, String className, @Nonnull Set<String> alreadyVisited) {
        ModelFieldSet fields = fieldMap.get(className);

        if (fields == null) {
            fields = new ModelFieldSet(new HashSet<ModelField>());
        }

        ModelFieldSet
                fieldsToAdd = new ModelFieldSet(new HashSet<ModelField>()),
                fieldsWithPrefixes = new ModelFieldSet(new HashSet<ModelField>());

        for (ModelField field : fields) {
            if (fieldMap.containsKey(field.getType()) && !alreadyVisited.contains(field.getType())) {
                alreadyVisited.add(field.getType());
                fieldsToAdd.addAll(spiderFields(field.getParameterKey() + ".", field.getType(), alreadyVisited));
            }
        }

        for (ModelField field : fieldsToAdd.addAll(fields)) {
            fieldsWithPrefixes.add(new ModelField(field.getType(), prefix + field.getParameterKey()));
        }

        return fieldsWithPrefixes;
    }

    @Nonnull
    public List<ModelField> getFieldsFromMethodCalls(@Nullable String methodCalls, @Nullable ModelField initialField) {
        List<ModelField> fields = new ArrayList<>();


        if (methodCalls != null && initialField != null) {
            fields.add(initialField);

            ModelField currentField = initialField;
            String editedCalls = methodCalls;

            if (methodCalls.startsWith(initialField.getParameterKey())) {
                editedCalls = methodCalls.substring(initialField.getParameterKey().length());
            }

            String[] calls = editedCalls.split("(\\(\\))");

            for (String call : calls) {
                if (call != null && !call.isEmpty()) {
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

    private void addSuperClassFieldsToModels(@Nonnull Map<String, String> superClassMap) {
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
            for (Map.Entry<String, String> entry : superClassMap.entrySet()) {
                if (done.contains(entry.getValue())) {
                    fieldMap.get(entry.getKey()).addAll(fieldMap.get(entry.getValue()));
                    done.add(entry.getKey());
                }
            }
            superClassMap.keySet().removeAll(done);
        }
    }

    @Nullable
    private String getParameterFromBeanAccessor(@Nonnull String methodCall) {

        String propertyName = null;

        if (methodCall.startsWith(".get")) {
            propertyName = methodCall.substring(4);
            propertyName = propertyName.substring(0, 1).toLowerCase() + propertyName.substring(1);
        }

        return propertyName;
    }

    @Override
    public String toString() {
        return fieldMap.toString();
    }
}