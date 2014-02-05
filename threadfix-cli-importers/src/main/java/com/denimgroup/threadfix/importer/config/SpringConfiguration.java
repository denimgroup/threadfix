package com.denimgroup.threadfix.importer.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:/jdbc.properties")
@ImportResource({"classpath:/offline-context.xml", "classpath:/applicationContext-hibernate.xml"})
public class SpringConfiguration {
}
