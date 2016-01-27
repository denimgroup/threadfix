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
package com.denimgroup.threadfix.framework.impl.model;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mac on 8/27/14.
 */
public final class FieldSetLookupUtils {

    private static final SanitizedLogger LOG = new SanitizedLogger(FieldSetLookupUtils.class);

    private FieldSetLookupUtils() {}

    /**
     * This method uses recursion to walk the tree of possible parameters that the spring
     * controller will accept and bind to the model object. This information should be
     * added in addition to all of the normal parameters (@RequestMapping, @PathVariable)
     */
    public static ModelFieldSet getPossibleParametersForModelType(Map<String, ModelFieldSet> fieldMap, String className) {
        ModelFieldSet fields = fieldMap.get(className);

        if (fields == null) {
            fields = new ModelFieldSet();
        }

        Set<String> alreadyVisited = set();
        alreadyVisited.add(className);

        ModelFieldSet fieldsToAdd = new ModelFieldSet(), finalFieldSet = new ModelFieldSet();

        // traverse the models to get properties
        for (ModelField field : fields) {
            if (fieldMap.containsKey(field.getType()) && !alreadyVisited.contains(field.getType())) {
                alreadyVisited.add(field.getType());
                fieldsToAdd.addAll(spiderFields(fieldMap, field.getParameterKey() + ".", field.getType(), alreadyVisited));
            }
        }

        // remove properties that are model objects themselves; we can't bind directly to these
        for (ModelField field : fields.addAll(fieldsToAdd)) {
            if (!fieldMap.containsKey(field.getType())) {
                finalFieldSet.add(field);
            }
        }

        return finalFieldSet;
    }

    @Nonnull
    private static ModelFieldSet spiderFields(Map<String, ModelFieldSet> fieldMap,
                                              String prefix,
                                              String className,
                                              @Nonnull Set<String> alreadyVisited) {

        ModelFieldSet fields =
                fieldMap.get(className) == null ?
                        new ModelFieldSet() :
                        fieldMap.get(className);

        ModelFieldSet
                fieldsToAdd = new ModelFieldSet(),
                fieldsWithPrefixes = new ModelFieldSet();

        for (ModelField field : fields) {
            if (fieldMap.containsKey(field.getType()) && !alreadyVisited.contains(field.getType())) {
                alreadyVisited.add(field.getType());
                fieldsToAdd.addAll(spiderFields(fieldMap, field.getParameterKey() + ".", field.getType(), alreadyVisited));
            }
        }

        for (ModelField field : fieldsToAdd.addAll(fields)) {
            fieldsWithPrefixes.add(new ModelField(field.getType(), prefix + field.getParameterKey()));
        }

        return fieldsWithPrefixes;
    }


    public static void addSuperClassFieldsToModels(@Nonnull Map<String, ModelFieldSet> fieldMap,
                                                   @Nonnull Map<String, String> superClassMap) {
        Set<String> done = set();

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
                    ModelFieldSet modelFields = fieldMap.get(entry.getKey());
                    if (modelFields != null) {
                        if (fieldMap.containsKey(entry.getValue())) {
                            modelFields.addAll(fieldMap.get(entry.getValue()));
                        } else {
                            LOG.error("Missing mapping for " + entry.getValue() +
                                    ". ThreadFix is unable to properly generate parameters until this bug is fixed.");
                        }
                    }
                    done.add(entry.getKey());
                }
            }
            superClassMap.keySet().removeAll(done);
        }
    }

}
