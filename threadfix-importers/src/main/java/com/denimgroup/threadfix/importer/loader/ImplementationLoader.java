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

import java.lang.annotation.Annotation;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * Created by mac on 11/18/14.
 */
public class ImplementationLoader<A extends Annotation, C> {

    private static final SanitizedLogger LOG = new SanitizedLogger(ImplementationLoader.class);

    private Map<String, Class<?>> classMap = newMap();
    private final Class<C> concreteClass;

    public ImplementationLoader(Class<A> annotationClass,
                                Class<C> concreteClass,
                                String packageName,
                                AnnotationKeyGenerator<A> keyGenerator) {

        LOG.info("Loading " + annotationClass + " annotation entries with concrete class " + concreteClass);

        Map<Class<?>, A> implementationMap = AnnotationLoader.getMap(annotationClass, packageName);

        for (Map.Entry<Class<?>, A> entry : implementationMap.entrySet()) {
            classMap.put(keyGenerator.getKey(entry.getValue()), entry.getKey());
        }

        this.concreteClass = concreteClass;
    }

    // TODO maybe cache constructors
    public C getImplementation(String key) {
        Class<?> channelImporterClass = classMap.get(key);

        try {
            assert channelImporterClass != null : "Got null class for key " + key;

            Constructor<?>[] constructors = channelImporterClass.getConstructors();

            assert constructors.length == 1 : "Got " + constructors.length + " constructors.";

            Object maybeClass = constructors[0].newInstance();

            if (concreteClass.isInstance(maybeClass)) {
                return concreteClass.cast(maybeClass);
            } else {
                throw new IllegalStateException(maybeClass +
                        " didn't implement " + concreteClass + ". Fix your code and try again.");
            }
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
            LOG.error("Encountered exception while loading classes.", e);
            throw new IllegalStateException(e);
        }
    }

}
