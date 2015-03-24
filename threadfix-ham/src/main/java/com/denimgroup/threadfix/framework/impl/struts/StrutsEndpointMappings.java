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
package com.denimgroup.threadfix.framework.impl.struts;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.full.EndpointGenerator;
import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.framework.impl.model.ModelField;
import com.denimgroup.threadfix.framework.impl.struts.model.StrutsAction;
import com.denimgroup.threadfix.framework.impl.struts.model.StrutsPackage;
import com.denimgroup.threadfix.framework.util.FilePathUtils;
import com.denimgroup.threadfix.framework.util.java.EntityMappings;
import com.denimgroup.threadfix.framework.util.java.EntityParser;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class StrutsEndpointMappings implements EndpointGenerator {

    private final String STRUTS_CONFIG_NAME = "struts.xml";
    private final String STRUTS_PROPERTIES_NAME = "struts.properties";

    private File rootDirectory;
    private Collection<File> javaFiles;
    private List<StrutsPackage> strutsPackages;
    private String strutsActionExtension;
    private EntityMappings entityMappings;
    private List<Endpoint> endpoints;

    public StrutsEndpointMappings(@Nonnull File rootDirectory) {
        this.rootDirectory = rootDirectory;
//        urlToControllerMethodsMap = map();
        File strutsConfigFile = null;
        File strutsPropertiesFile = null;

        entityMappings = new EntityMappings(rootDirectory);

        if (rootDirectory.exists()) {
            javaFiles = FileUtils.listFiles(rootDirectory,
                    new FileExtensionFileFilter("java"), TrueFileFilter.TRUE);
        } else {
            javaFiles = Collections.emptyList();
        }

        String[] configExtensions = {"xml", "properties"};
        Collection configFiles = FileUtils.listFiles(rootDirectory, configExtensions, true);

        for (Iterator iterator = configFiles.iterator(); iterator.hasNext();) {
            File file = (File) iterator.next();
            if (file.getName().equals(STRUTS_CONFIG_NAME))
                strutsConfigFile = file;
            if (file.getName().equals(STRUTS_PROPERTIES_NAME))
                strutsPropertiesFile = file;
            if (strutsConfigFile != null && strutsPropertiesFile != null)
                break;
        }

        strutsActionExtension = StrutsPropertiesParser.getStrutsProperties(strutsPropertiesFile)
                .getProperty("struts.action.extension","action");
        if (strutsActionExtension == null)
            strutsActionExtension = "";
        strutsActionExtension = strutsActionExtension.trim();
        if (strutsActionExtension.length() > 0
                && !strutsActionExtension.startsWith(".")) {
            strutsActionExtension = "." + strutsActionExtension;
        }

        strutsPackages = StrutsXmlParser.parse(strutsConfigFile);

        generateMaps();

    }

    private void generateMaps() {
        endpoints = list();
        for (StrutsPackage strutsPackage : strutsPackages) {
            String namespace = strutsPackage.getNamespace();
            for (StrutsAction strutsAction : strutsPackage.getActions()) {
                StringBuilder sbUrl = new StringBuilder(namespace);
                String actionName = strutsAction.getName();

                sbUrl.append("/");
                sbUrl.append( actionName );
                sbUrl.append( strutsActionExtension );

                if (strutsAction.getActClass() == null)
                    continue;

                File actionFile = getJavaFileByName(strutsAction.getActClass());
                String modelName = actionFile.getName().substring(0,actionFile.getName().lastIndexOf(".java"));
                EntityParser entityParser = EntityParser.parse(actionFile);
                String filePath = FilePathUtils.getRelativePath(actionFile, rootDirectory);
                Set<ModelField> fieldMappings = entityMappings.getPossibleParametersForModelType(modelName).getFieldSet();
                List<String> httpMethods = list();
                List<String> parameters = list();

                String urlPath = sbUrl.toString();

                if (urlPath.contains("*")) { // wildcard
                    for (String ep : entityParser.getMethods()) {
                        urlPath = sbUrl.toString();
                        httpMethods = list();
                        parameters = list();
                        if ("execute".equals(ep)) {
                            urlPath = urlPath.replace("!*", "");
                            urlPath = urlPath.replace("*", "");
                            httpMethods.add("GET");
                            endpoints.add(new StrutsEndpoint(filePath, urlPath, httpMethods, parameters));
                        } else {
                            urlPath = urlPath.replace("*", ep);
                            httpMethods.add("POST");
                            for (ModelField mf : fieldMappings) {
                                parameters.add(mf.getParameterKey());
                            }
                            endpoints.add(new StrutsEndpoint(filePath, urlPath, httpMethods, parameters));
                        }
                    }
                } else {
                    httpMethods.add("POST");
                    for (ModelField mf : fieldMappings) {
                        parameters.add(mf.getParameterKey());
                    }
                    endpoints.add(new StrutsEndpoint(filePath, urlPath, httpMethods, parameters));
                }
            }
        }

    }

    private File getJavaFileByName(String fileName) {
        fileName = fileName.replace('.', '/');
        fileName = fileName.concat(".java");
        for (File f : javaFiles) {
            String filePath = f.getPath();
            if (filePath.contains("\\"))
                filePath = filePath.replace('\\','/');
            if (filePath.endsWith(fileName))
                return f;
        }
        return null;
    }

    @Nonnull
    @Override
    public List<Endpoint> generateEndpoints() {
        return endpoints;
    }

    /**
     * Returns an iterator over a set of elements of type T.
     *
     * @return an Iterator.
     */
    @Override
    public Iterator<Endpoint> iterator() {
        return generateEndpoints().iterator();
    }
}
