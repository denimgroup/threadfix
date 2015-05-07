package com.denimgroup.threadfix.service.email;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Map;

import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.exception.MethodInvocationException;
import org.apache.velocity.exception.ParseErrorException;
import org.apache.velocity.exception.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.service.EmailBuilderService;

@Service
public class EmailBuilderServiceImpl implements EmailBuilderService {

	@Autowired
	private VelocityEngine velocityEngine;

	/**
	 * This Function uses the velocity template engine to build an email body from a template and a model
	 */
	@Override
	public String prepareMessageFromTemplate(Map<String,Object> model, String templateName){
		VelocityContext context = new VelocityContext();

		for (String key : model.keySet()){
			context.put(key, model.get(key));
		}

		Template template = null;
		try {
			template = velocityEngine.getTemplate(templateName);
		} catch (ResourceNotFoundException e) {
			e.printStackTrace();
		} catch (ParseErrorException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		StringWriter stringWriter = new StringWriter();
		try {
			template.merge( context, stringWriter );
		} catch (ResourceNotFoundException e) {
			e.printStackTrace();
		} catch (ParseErrorException e) {
			e.printStackTrace();
		} catch (MethodInvocationException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return stringWriter.toString();
	}
}
