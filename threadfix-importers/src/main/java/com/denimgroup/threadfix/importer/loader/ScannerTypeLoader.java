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
package com.denimgroup.threadfix.importer.loader;

import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.filter.AnnotationTypeFilter;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by mac on 9/16/14.
 */
public final class ScannerTypeLoader {

    private static Map<ScanImporter, Class<?>> savedMap = null;

    @Nonnull
    public static Map<ScanImporter, Class<?>> getMap() {
        if (savedMap == null) {
            initMap();
        }

        assert savedMap != null : "Saved map was null after initialization.";

        return savedMap;
    }

    private static final SanitizedLogger LOG = new SanitizedLogger(ScannerTypeLoader.class);

    private static void initMap() {

        savedMap = newMap();

        ClassPathScanningCandidateComponentProvider provider =
                new ClassPathScanningCandidateComponentProvider(false);

        provider.addIncludeFilter(new AnnotationTypeFilter(ScanImporter.class));

        ClassLoader classLoader = ScannerTypeLoader.class.getClassLoader();
        provider.setResourceLoader(new PathMatchingResourcePatternResolver(classLoader));

        Set<BeanDefinition> candidateComponents = provider.findCandidateComponents("com.denimgroup.threadfix.importer.impl.upload");

        for (BeanDefinition candidateComponent : candidateComponents) {
            candidateComponent.getBeanClassName();
            try {

                Class<?> scannerClass = Class.forName(candidateComponent.getBeanClassName());

                ScanImporter scannerType = scannerClass.getAnnotation(ScanImporter.class);

                assert scannerType != null : "Unable to get scanner type from annotation, something is wrong.";

                LOG.info("Successfully loaded " + scannerClass + " from classpath.");

                savedMap.put(scannerType, scannerClass);

            } catch (ClassNotFoundException e) {
                LOG.error("Class " + candidateComponent + " wasn't loadable even though we found it with " +
                        "ClassPathScanningCandidateComponentProvider. Something is wrong.");
                throw new IllegalStateException(e);
            }
        }

        assert !savedMap.isEmpty() : "Map was empty after loading annotations from classpath.";
    }

}
