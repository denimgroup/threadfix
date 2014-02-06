package com.denimgroup.threadfix.importer.config;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:/jdbc.properties")
@ImportResource({"classpath:/offline-context.xml", "classpath:/applicationContext-hibernate.xml"})
public class SpringConfiguration {

    private static AnnotationConfigApplicationContext context = null;

    public static AnnotationConfigApplicationContext getContext() {
        if (context == null) {
            context = new AnnotationConfigApplicationContext();
            context.register(SpringConfiguration.class);
            context.refresh();
        }
        return context;
    }

}
