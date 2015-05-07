package com.denimgroup.threadfix.service.email;

import java.util.Properties;

import javax.annotation.Resource;
import javax.servlet.ServletContext;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.PropertiesFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import com.denimgroup.threadfix.logging.SanitizedLogger;

@Configuration
@ComponentScan("com.denimgroup.threadfix")
public class EmailServicesSetup {

	private static final SanitizedLogger LOG = new SanitizedLogger(EmailServicesSetup.class);

	@Autowired
	private ServletContext servletContext;
	@Autowired
	private EmailConfiguration emailConfiguration;
	@Resource(name = "emailProperties")
	private Properties emailProperties;

	@Bean(name = "emailProperties")
	public PropertiesFactoryBean mapper() {
	    PropertiesFactoryBean bean = new PropertiesFactoryBean();
	    bean.setLocation(new ClassPathResource("email.properties"));
	    return bean;
	}

	@Bean
	public JavaMailSender mailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setJavaMailProperties(emailProperties);//so we don't have to hard code all the properties we want to be able to use
        //the following lines are required by the implementation of javaMailSenderImpl
        mailSender.setHost(emailProperties.getProperty("mail.host"));
        mailSender.setUsername(emailProperties.getProperty("mail.username"));
        mailSender.setPassword(emailProperties.getProperty("mail.password"));
        String port = emailProperties.getProperty("mail.port");
        if (port!=null && !port.isEmpty()) mailSender.setPort(Integer.parseInt(port));

		if ( mailSender.getHost() == null ) {
			LOG.info("email is not configured");
			emailConfiguration.setConfiguredEmail(false);
		}
		else {
			LOG.info("email is configured");
			emailConfiguration.setConfiguredEmail(true);
		}
		return mailSender;
	}

	@Bean
	public EmailFilterService emailFilterService(){
		EmailFilterService emailFilterService = new EmailFilterService();
		if (emailProperties.getProperty("custom.filters")!=null && !emailProperties.getProperty("custom.filters").isEmpty()){
			emailFilterService.parseFilters(emailProperties.getProperty("custom.filters"));
		}
		else {
			LOG.info("No email filters were set in email properties");
		}
		return emailFilterService;
	}

	@Bean
	public VelocityEngine velocityEngine() {
		VelocityEngine velocityEngine = new VelocityEngine();
		velocityEngine.addProperty(RuntimeConstants.RESOURCE_LOADER, "webapp");
		velocityEngine.addProperty("webapp.resource.loader.class", "org.apache.velocity.tools.view.WebappResourceLoader");
		velocityEngine.addProperty("webapp.resource.loader.path", "/velocityTemplates/");
		velocityEngine.setApplicationAttribute("javax.servlet.ServletContext", servletContext);
		try {
			velocityEngine.init();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return velocityEngine;
	}
}
