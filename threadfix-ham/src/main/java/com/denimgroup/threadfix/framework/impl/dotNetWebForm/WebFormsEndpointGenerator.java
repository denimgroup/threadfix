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

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by mac on 9/4/14.
 */
public class WebFormsEndpointGenerator implements EndpointGenerator {

    private List<Endpoint> endpoints = list();

    public WebFormsEndpointGenerator(@Nonnull File rootDirectory) {
        if (!rootDirectory.exists() || !rootDirectory.isDirectory()) {
            throw new IllegalArgumentException("Invalid directory passed to WebFormsEndpointGenerator: " + rootDirectory);
        }

        Map<String, AscxFile> map = AscxFileMappingsFileParser.getMap(rootDirectory);

        Collection aspxFiles = FileUtils.listFiles(rootDirectory,
                new FileExtensionFileFilter("aspx"), TrueFileFilter.INSTANCE);

        List<AspxParser> aspxParsers = list();

        for (Object aspxFile : aspxFiles) {
            if (aspxFile instanceof File) {
                File file = (File) aspxFile;

                AspxParser aspxParser = AspxParser.parse(file);
                AspxUniqueIdParser uniqueIdParser = AspxUniqueIdParser.parse(file, map);

                aspxParser.parameters.addAll(uniqueIdParser.parameters);
                aspxParsers.add(aspxParser);
            }
        }

        Collection aspxCsFiles = FileUtils.listFiles(rootDirectory,
                new FileExtensionFileFilter("aspx.cs"), TrueFileFilter.INSTANCE);

        List<AspxCsParser> aspxCsParsers = list();

        for (Object aspxCsFile : aspxCsFiles) {
            if (aspxCsFile instanceof File) {
                aspxCsParsers.add(AspxCsParser.parse((File) aspxCsFile));
            }
        }

        collapseToEndpoints(aspxCsParsers, aspxParsers);
    }

    public WebFormsEndpointGenerator(Collection<AspxCsParser> csParsers, Collection<AspxParser> aspxParsers) {
        collapseToEndpoints(csParsers, aspxParsers);
    }

    void collapseToEndpoints(Collection<AspxCsParser> csParsers, Collection<AspxParser> aspxParsers) {
        Map<String, AspxParser> aspxParserMap = newMap();
        Map<String, AspxCsParser> aspxCsParserMap = newMap();

        for (AspxCsParser csParser : csParsers) {
            aspxCsParserMap.put(csParser.aspName, csParser);
        }

        for (AspxParser aspxParser : aspxParsers) {
            aspxParserMap.put(aspxParser.aspName, aspxParser);
        }

        for (Map.Entry<String, AspxParser> entry : aspxParserMap.entrySet()) {
            String key = entry.getKey() + ".cs";
            if (aspxCsParserMap.containsKey(key)) {
                endpoints.add(new WebFormsEndpoint(entry.getValue(), aspxCsParserMap.get(key)));
            }
        }
    }

    @Nonnull
    @Override
    public List<Endpoint> generateEndpoints() {
        return endpoints;
    }

    @Override
    public Iterator<Endpoint> iterator() {
        return endpoints.iterator();
    }
}
