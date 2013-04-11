package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;

public class ControllerUtils {
	
	private static final String SUCCESS_MESSAGE = "successMessage";
	private static final String ERROR_MESSAGE = "errorMessage";

	private ControllerUtils() {
		// Nobody can instantiate this class
	}

	public static Object getErrorMessage(HttpServletRequest request) {
		return getAttribute(request, ERROR_MESSAGE);
	}
	
	public static Object getSuccessMessage(HttpServletRequest request) {
		return getAttribute(request, SUCCESS_MESSAGE);
	}
	
	public static void addSuccessMessage(HttpServletRequest request, String successMessage) {
		addMessage(request, SUCCESS_MESSAGE, successMessage);
	}
	
	public static void addErrorMessage(HttpServletRequest request, String successMessage) {
		addMessage(request, ERROR_MESSAGE, successMessage);
	}
	
	private static Object getAttribute(HttpServletRequest request, String attribute) {
		if (request == null || attribute == null) {
			return null;
		}
		
		Object returnValue = null;
		if (request.getSession() != null) {
			returnValue = request.getSession().getAttribute(attribute);
			if (returnValue != null) {
				request.getSession().removeAttribute(attribute);
			}
		}
		
		return returnValue;
	}
	
	private static void addMessage(HttpServletRequest request, String key, String message) {
		if (request == null || message == null) {
			return;
		}
		
		if (request.getSession() != null) {
			request.getSession().setAttribute(key, message);
		}
	}
}
