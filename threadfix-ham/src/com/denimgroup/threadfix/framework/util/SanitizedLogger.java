package com.denimgroup.threadfix.framework.util;

/**
 * This method provides a single point of access to the loggers to ease sanitization efforts.
 * Just use one of the constructors and use it like a normal logger.
 * @author mcollins
 *
 */
public class SanitizedLogger {
	
	//private final String className;
	
	public SanitizedLogger(String className) {
		//this.className = className;
	}
	
	public SanitizedLogger(Class<?> className) {
		//this.className = className.toString();
	}
	
	/**
	 * The longer form is used for the below methods so that the original line number is reported.
	 * @param message
	 */
	public void debug(String message) {
		System.out.println(message);
	}
	
	public void debug(String message, Throwable ex) {
		System.out.println(message);
	}
	
	public void info(String message) {
		System.out.println(message);
	}
	
	public void info(String message, Throwable ex) {
		System.out.println(message);
	}
	
	public void warn(String message) {
		System.out.println(message);
	}
	
	public void warn(String message, Throwable ex) {
		System.out.println(message);
	}
	
	public void error(String message) {
		System.out.println(message);
	}
	
	public void error(String message, Throwable ex) {
		System.out.println(message);
	}
	
}
