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
package com.denimgroup.threadfix.framework.impl.dotNet;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 6/16/14.
 */
public class DotNetMappings implements EndpointGenerator {

    final Collection<File> cSharpFiles;
    final File             rootDirectory;

    DotNetRouteMappings routeMappings = null;
    List<DotNetControllerMappings> controllerMappingsList = list();
    DotNetEndpointGenerator generator = null;

    @SuppressWarnings("unchecked")
    public DotNetMappings(@Nonnull File rootDirectory) {
        assert rootDirectory.exists() : "Root file did not exist.";
        assert rootDirectory.isDirectory() : "Root file was not a directory.";

        this.rootDirectory = rootDirectory;

        cSharpFiles = FileUtils.listFiles(rootDirectory,
                new FileExtensionFileFilter("cs"), TrueFileFilter.INSTANCE);

        generateMappings();
    }

    private void generateMappings() {

        List<ViewModelParser> modelParsers = list();

        for (File file : cSharpFiles) {
            if (file != null && file.exists() && file.isFile() &&
                    file.getAbsolutePath().contains(rootDirectory.getAbsolutePath())) {

                DotNetControllerParser endpointParser = new DotNetControllerParser(file);
                DotNetRoutesParser routesParser = new DotNetRoutesParser();
                ViewModelParser modelParser = new ViewModelParser();
                EventBasedTokenizerRunner.run(file, endpointParser, routesParser, modelParser);

                if (routesParser.hasValidMappings()) {
                    assert routeMappings == null; // if the project has 2 routes files we want to know about it
                    routeMappings = routesParser.mappings;
                }

                if (endpointParser.hasValidControllerMappings()) {
                    controllerMappingsList.add(endpointParser.mappings);
                }

                modelParsers.add(modelParser);
            }
        }

        DotNetModelMappings modelMappings = new DotNetModelMappings(modelParsers);

        generator = new DotNetEndpointGenerator(routeMappings, modelMappings, controllerMappingsList);
    }

    @Nonnull
    @Override
    public List<Endpoint> generateEndpoints() {
        assert generator != null;

        // We can't count on -ea being on
        return generator == null ? new ArrayList<Endpoint>() : generator.generateEndpoints();
    }

    @Override
    public Iterator<Endpoint> iterator() {
        assert generator != null;

        // We can't count on -ea being on
        return generator == null ? new ArrayList<Endpoint>().iterator() : generator.iterator();
    }
}
