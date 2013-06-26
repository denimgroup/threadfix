package com.denimgroup.threadfix.service;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

/**
 * This method provides a single point of access to the loggers to ease sanitization efforts.
 * Just use one of the constructors and use it like a normal logger.
 * @author mcollins
 *
 */
public class SanitizedLogger {
	
	private final Logger log;
	private static final String MY_CANONICAL_CLASS_NAME = SanitizedLogger.class.getCanonicalName();
	
	public SanitizedLogger(String className) {
		log = Logger.getLogger(className);
	}
	
	public SanitizedLogger(Class<?> className) {
		log = Logger.getLogger(className);
	}
	
	/**
	 * The longer form is used for the below methods so that the original line number is reported.
	 * @param message
	 */
	public void debug(String message) {
		log.log(MY_CANONICAL_CLASS_NAME, Level.DEBUG, sanitize(message), null);
	}
	
	public void debug(String message, Throwable ex) {
		log.log(MY_CANONICAL_CLASS_NAME, Level.DEBUG, sanitize(message), ex);
	}
	
	public void info(String message) {
		log.log(MY_CANONICAL_CLASS_NAME, Level.INFO, sanitize(message), null);
	}
	
	public void info(String message, Throwable ex) {
		log.log(MY_CANONICAL_CLASS_NAME, Level.INFO, sanitize(message), ex);
	}
	
	public void warn(String message) {
		log.log(MY_CANONICAL_CLASS_NAME, Level.WARN, sanitize(message), null);
	}
	
	public void warn(String message, Throwable ex) {
		log.log(MY_CANONICAL_CLASS_NAME, Level.WARN, sanitize(message), ex);
	}
	
	public void error(String message) {
		log.log(MY_CANONICAL_CLASS_NAME, Level.ERROR, sanitize(message), null);
	}
	
	public void error(String message, Throwable ex) {
		log.log(MY_CANONICAL_CLASS_NAME, Level.ERROR, sanitize(message), ex);
	}
	
	/**
	 * Blacklist. Should probably be a whitelist but I'm not 
	 * sure what else needs to be sanitized.
	 * @param startString
	 * @return
	 */
	private String sanitize(String startString) {
		String retVal;
		
		if(startString == null) {
			retVal = "<NULL>";
		} else {
			retVal = startString.replace("\n", "\\n").replace("\t","\\t").trim();
		}
		
		return(retVal);
	}
	
}
