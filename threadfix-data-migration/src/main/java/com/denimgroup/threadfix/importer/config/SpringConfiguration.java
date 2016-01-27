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

package com.denimgroup.threadfix.importer.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.dao.annotation.PersistenceExceptionTranslationPostProcessor;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.hibernate3.HibernateTransactionManager;
import org.springframework.orm.hibernate3.annotation.AnnotationSessionFactoryBean;
import org.springframework.orm.hibernate3.support.IdTransferringMergeEventListener;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.util.ClassUtils;

import javax.sql.DataSource;
import java.util.Map;
import java.util.Properties;

import static com.denimgroup.threadfix.CollectionUtils.map;

@Configuration
@EnableTransactionManagement(proxyTargetClass = false)
@PropertySource("file:jdbc_temp.properties")
public class SpringConfiguration {

    @Value("${jdbc.driverClassName}")
    private String driverClassName;

    @Value("${jdbc.url}")
    private String jdbcUrl;

    @Value("${jdbc.username}")
    private String jdbcUsername;

    @Value("${jdbc.password}")
    private String jdbcPassword;

    @Value("${hibernate.dialect}")
    private String hibernateDialect;

    @Value("${hibernate.show_sql}")
    private String hibernateShow_sql;

    @Value("${hibernate.hbm2ddl.auto}")
    private String hibernateHbm2ddlAuto;

    private static AnnotationConfigApplicationContext context = null;

    public static AnnotationConfigApplicationContext getContext() {
        if (context == null) {
            context = new AnnotationConfigApplicationContext();
            context.register(SpringConfiguration.class);
            context.scan("com.denimgroup.threadfix");
            context.setClassLoader(SpringConfiguration.class.getClassLoader());
            context.refresh();
        }
        return context;
    }

    /**
     *
     * WARNING this class initializes the classloader every time. If you need a reference to the
     * properly configured instance later, use the 0-arity version.
     *
     * This method is available for plugins with complicated classloader schemes.
     * If ClassUtils.getDefaultClassLoader() returns a classloader that doesn't load the plugin
     * dependencies, it can break the plugin support. The safe way to use this method is generally
     *
     * initializeWithClassLoader(CallingClass.class.getClassLoader());
     *
     * @param classLoader a classloader that has access to TF classes
     * @return the Spring context
     */
    public static AnnotationConfigApplicationContext initializeWithClassLoader(ClassLoader classLoader) {

        // This is internal Spring magic. ClassUtils is the class used to load Spring JDBC classes
        ClassUtils.overrideThreadContextClassLoader(classLoader);

        context = new AnnotationConfigApplicationContext();
        context.setClassLoader(classLoader);
        context.scan("com.denimgroup.threadfix");
        context.register(SpringConfiguration.class);
        context.refresh();
        return context;
    }

    public static <T> T getSpringBean(Class<T> targetClass) {
        return getContext().getBean(targetClass);
    }

    @Bean
    public DataSource dataSource() {

        final DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setUrl(jdbcUrl);
        ds.setUsername(jdbcUsername);
        ds.setPassword(jdbcPassword);
        ds.setDriverClassName(driverClassName);

        return ds;
    }

    @Bean
    public PropertiesFactoryBean propertiesFactoryBean() {
        final PropertiesFactoryBean bean = new PropertiesFactoryBean();

        Properties properties = getHibernateProperties();

        bean.setProperties(properties);

        return bean;
    }

    private Properties getHibernateProperties() {
        Properties properties = new Properties();

        properties.put("hibernate.dialect", hibernateDialect);
        properties.put("hibernate.show_sql", hibernateShow_sql);
        properties.put("hibernate.hbm2ddl.auto", hibernateHbm2ddlAuto);

        return properties;
    }

    @Bean
    public AnnotationSessionFactoryBean annotationSessionFactoryBean() {
        AnnotationSessionFactoryBean bean = new AnnotationSessionFactoryBean();

        bean.setDataSource(dataSource());
        bean.setPackagesToScan("com.denimgroup.threadfix.data.entities");
        bean.setHibernateProperties(getHibernateProperties());
        Map<String, Object> merge = map("merge", (Object) new IdTransferringMergeEventListener());
        bean.setEventListeners(merge);

        return bean;
    }

    @Bean
    public HibernateTransactionManager getHibernateTransactionManager() {
        HibernateTransactionManager hibernateTransactionManager = new HibernateTransactionManager();
        hibernateTransactionManager.setSessionFactory(annotationSessionFactoryBean().getObject());
        return hibernateTransactionManager;
    }

    @Bean
    public static PropertySourcesPlaceholderConfigurer placeHolderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Bean
    public PersistenceExceptionTranslationPostProcessor getPersistenceExceptionTranslationPostProcessor() {
        return new PersistenceExceptionTranslationPostProcessor();
    }

}
