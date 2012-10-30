package com.denimgroup.threadfix.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.Properties;

import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.webapp.viewmodels.DefaultsConfigModel;

@Service
public class DefaultConfigServiceImpl implements DefaultConfigService {
	
	protected final SanitizedLogger log = new SanitizedLogger(DefaultConfigServiceImpl.class);

	@Override
	public DefaultsConfigModel loadCurrentConfiguration() {
		Properties defaultsProperties = new Properties();
		InputStream inputStream = null;
		try {
			inputStream = new FileInputStream(new File("defaults.properties"));
		} catch (IOException e) {
			log.warn("An IOException was thrown while trying to construct " +
					"an InputStream for the properties file.", e);
		}
		
		//this.getClass().getResourceAsStream("/defaults.properties");
		
		if (inputStream != null) {
			try {
				defaultsProperties.load(inputStream);
			} catch (IOException e) {
				log.warn("Encountered IOException while loading security configuration.",e);
			}
			
			try {
				inputStream.close();
			} catch (IOException e) {
				// Oops
				log.warn("IOException encountered while trying to close an InputStream.",e);
			}
		}
		
		
		return new DefaultsConfigModel(defaultsProperties);
	}

	@Override
	public void saveConfiguration(DefaultsConfigModel model) {
		log.info("Saving default configuration.");
		
		OutputStream outputStream = null;
		
		try {
			outputStream = new FileOutputStream("defaults.properties");
		} catch (FileNotFoundException e) {
			log.warn("A FileNotFoundException was thrown while trying to construct " +
					"a FileOutputStream for the properties file.", e);
		}
		
		if (outputStream != null) {
			try {
				model.getProperties().store(outputStream, "Saving default configuration at " + new Date());
			} catch (IOException e) {
				log.warn("IOException thrown while writing properties.",e);
			}
			
			try {
				outputStream.close();
			} catch (IOException e) {
				log.warn("IOException thrown while trying to close the output stream.",e);
			}
		}
	}
}
