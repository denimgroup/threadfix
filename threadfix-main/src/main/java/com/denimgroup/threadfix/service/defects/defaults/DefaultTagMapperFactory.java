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

package com.denimgroup.threadfix.service.defects.defaults;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.entities.DefaultTag;
import com.denimgroup.threadfix.logging.SanitizedLogger;

@Service
public class DefaultTagMapperFactory {

	protected static final SanitizedLogger STATIC_LOG = new SanitizedLogger(DefaultTagMapperFactory.class);

	@Autowired
	private BeanFactory beanFactory;

	//This function loads the DefaultTagMapper bean from className
	public AbstractDefaultTagMapper getTagMapperFromClassName(String fullClassName){
		Exception exception = null;
		STATIC_LOG.debug("A tagMapper bean is being accessed by factory. Attempting to load using Class.forName() with " + fullClassName);

		try {
			Class<?> defaultTagMapperClass = Class.forName(fullClassName);
			return (AbstractDefaultTagMapper) beanFactory.getBean(defaultTagMapperClass);

		} catch (ClassNotFoundException e) {
			exception = e;
		} catch (BeansException e) {
			exception = e;
		} catch (ClassCastException e) {
			exception = e;
		}

		if (exception != null) {
			STATIC_LOG.error("The tag has not been correctly added. " +
					"Put the JAR in the lib directory of threadfix under the webapps folder in tomcat.", exception);
		}

		STATIC_LOG.warn("Failed to load a TagMapper implementation.");
		return null;
	}

	public AbstractDefaultTagMapper getTagMapperFromDefaultTag(DefaultTag defaultTag){
		return getTagMapperFromClassName(defaultTag.getFullClassName());
	}
}
