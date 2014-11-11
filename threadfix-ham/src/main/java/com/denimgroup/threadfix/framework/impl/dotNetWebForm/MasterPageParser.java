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
 * Created by mac on 10/27/14.
 */
public class MasterPageParser {

    private MasterPageParser(){}

    public static Map<String, AspxParser> getMasterFileMap(File rootDirectory) {
        Map<String, AscxFile> map = AscxFileMappingsFileParser.getMap(rootDirectory);
        return getMasterFileMap(rootDirectory, map);
    }

    public static Map<String, AspxParser> getMasterFileMap(File rootDirectory, Map<String, AscxFile> ascxFileMap) {
        if (rootDirectory == null) {
            throw new IllegalArgumentException("Can't pass null argument to getMasterFileMap()");
        } else if (!rootDirectory.isDirectory()) {
            throw new IllegalArgumentException("Can't pass a non-directory file argument to getMasterFileMap()");
        }

        Map<String, AspxParser> parserMap = newMap();

        Collection masterFiles = FileUtils.listFiles(rootDirectory,
                new FileExtensionFileFilter("Master"), TrueFileFilter.INSTANCE);

        for (Object aspxFile : masterFiles) {
            if (aspxFile instanceof File) {
                File file = (File) aspxFile;

                AspxParser aspxParser = AspxParser.parse(file);
                AspxUniqueIdParser uniqueIdParser = AspxUniqueIdParser.parse(file, ascxFileMap);

                aspxParser.parameters.addAll(uniqueIdParser.parameters);
                parserMap.put(file.getName(), aspxParser);
            }
        }

        return parserMap;
    }
}
