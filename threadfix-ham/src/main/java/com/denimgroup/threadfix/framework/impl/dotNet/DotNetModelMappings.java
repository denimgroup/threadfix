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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.framework.impl.model.FieldSetLookupUtils;
import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.impl.model.ModelFieldSet;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.framework.impl.model.FieldSetLookupUtils.addSuperClassFieldsToModels;

/**
 * Created by mac on 8/27/14.
 */
public class DotNetModelMappings {

    // This should be done by the end of the constructor
    @Nonnull
    private final Collection<ViewModelParser> modelParsers;

    @Nonnull
    private final Map<String, ModelFieldSet> fieldMap = map();

    // This version will parse all the Java files in the directory.
    @SuppressWarnings("unchecked")
    public DotNetModelMappings(@Nonnull File rootDirectory) {

        modelParsers = list();

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

    private void collapse() {
        Map<String, String> superClassMap = map();

        for (ViewModelParser parser : modelParsers) {
            for (Map.Entry<String, Set<ModelField>> entry : parser.map.entrySet()) {
                fieldMap.put(entry.getKey(), new ModelFieldSet(entry.getValue()));
            }

            superClassMap.putAll(parser.superClassMap);
        }

        addSuperClassFieldsToModels(fieldMap, superClassMap);
    }

    /**
     * This method uses recursion to walk the tree of possible parameters that the spring
     * controller will accept and bind to the model object. This information should be
     * added in addition to all of the normal parameters (@RequestMapping, @PathVariable)
     */
    public ModelFieldSet getPossibleParametersForModelType(String className) {
        return FieldSetLookupUtils.getPossibleParametersForModelType(fieldMap, className);
    }

    public boolean isEmpty() {
        return fieldMap.isEmpty();
    }

    @Override
    public String toString() {
        return fieldMap.toString();
    }
}