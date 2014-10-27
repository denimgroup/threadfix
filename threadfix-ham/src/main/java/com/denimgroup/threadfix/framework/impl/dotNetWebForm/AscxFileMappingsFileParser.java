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
package com.denimgroup.threadfix.framework.impl.dotNetWebForm;

import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import java.io.File;
import java.util.Collection;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by mac on 10/24/14.
 */
public class AscxFileMappingsFileParser {

    private AscxFileMappingsFileParser(){}

    public static Map<String, AscxFile> getMap(File rootDirectory) {
        if (!rootDirectory.exists() || !rootDirectory.isDirectory()) {
            throw new IllegalArgumentException("Invalid directory passed to WebFormsEndpointGenerator: " + rootDirectory);
        }

        Collection ascxFiles = FileUtils.listFiles(rootDirectory,
                new FileExtensionFileFilter("ascx"), TrueFileFilter.INSTANCE);

        Map<String, AscxFile> map = newMap();

        for (Object aspxFile : ascxFiles) {
            if (aspxFile instanceof File) {

                File file = (File) aspxFile;
                String name = file.getName();
                String key = name.contains(".") ? name.substring(0, name.indexOf('.')) : name;
                map.put(key, new AscxFile(file));
            }
        }

        return map;
    }
}
