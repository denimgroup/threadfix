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

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.filter.AnnotationTypeFilter;

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.listOf;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by mac on 9/16/14.
 */
public final class AnnotationLoader<T extends java.lang.annotation.Annotation> {

    private static final SanitizedLogger LOG = new SanitizedLogger(AnnotationLoader.class);

    public static <A extends Annotation> Map<Class<?>, A> getMap(Class<A> scanImporterClass, String packageName) {
        AnnotationLoader<A> loader = new AnnotationLoader<>();

        return loader.loadMap(scanImporterClass, packageName);
    }

    /**
     * Requires a 0-argument constructor
     * @param annotationClass The loaded classes must be annotation with this
     * @param packageName The loaded classes must be in this package or a subpackage
     * @param concreteClass The loaded classes must be a subclass of this class
     * @param <A> This is the annotation type parameter
     * @param <C> This is the concrete class type parameter
     * @return a list of concrete implementations of the classes
     */
    public static <A extends Annotation, C> List<C> getListOfConcreteClass(
            Class<A> annotationClass, String packageName, Class<C> concreteClass) {

        Map<Class<?>, A> map = getMap(annotationClass, packageName);

        List<C> returnList = listOf(concreteClass);

        try {
            for (Class<?> updaterClass : map.keySet()) {
                Constructor<?>[] constructors = updaterClass.getDeclaredConstructors();

                assert constructors.length == 1 : "Got " + constructors.length + " constructors.";

                Object maybeObject = constructors[0].newInstance();
                if (concreteClass.isInstance(maybeObject)) {
                    returnList.add(concreteClass.cast(maybeObject));
                } else {
                    throw new IllegalStateException(updaterClass +
                            " didn't implement " + concreteClass + ". Fix your code and try again.");
                }
            }

        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException("Got exception while instantiating code : ", e);
        }

        return returnList;
    }

    public Map<Class<?>, T> loadMap(Class<T> annotationClass, String packageName) {

        Map<Class<?>, T> savedMap = newMap();

        ClassPathScanningCandidateComponentProvider provider =
                new ClassPathScanningCandidateComponentProvider(false);

        provider.addIncludeFilter(new AnnotationTypeFilter(annotationClass));

        ClassLoader classLoader = AnnotationLoader.class.getClassLoader();
        provider.setResourceLoader(new PathMatchingResourcePatternResolver(classLoader));

        Set<BeanDefinition> candidateComponents = provider.findCandidateComponents(packageName);

        for (BeanDefinition candidateComponent : candidateComponents) {
            candidateComponent.getBeanClassName();
            try {

                Class<?> targetClass = Class.forName(candidateComponent.getBeanClassName());

                T annotation = targetClass.getAnnotation(annotationClass);

                assert annotation != null :
                        "Unable to get " + annotationClass.getName() + " annotation for class " +
                                candidateComponent.getBeanClassName() +
                                ", something is wrong.";

                LOG.info("Successfully loaded " + targetClass + " from classpath.");

                savedMap.put(targetClass, annotation);

            } catch (ClassNotFoundException e) {
                LOG.error("Class " + candidateComponent + " wasn't loadable even though we found it with " +
                        "ClassPathScanningCandidateComponentProvider. Something is wrong.");
                throw new IllegalStateException(e);
            }
        }

        assert !savedMap.isEmpty() : "Map was empty after loading annotations from classpath.";

        return savedMap;
    }

}
