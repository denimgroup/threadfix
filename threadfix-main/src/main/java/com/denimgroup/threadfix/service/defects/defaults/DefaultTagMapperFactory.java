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
