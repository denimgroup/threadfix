package com.denimgroup.threadfix.service.util;

import javax.servlet.http.HttpServletRequest;

public final class ControllerUtils {
	
	private static final String SUCCESS_MESSAGE = "successMessage";
	private static final String ERROR_MESSAGE = "errorMessage";
    private static final String ACTIVE_TAB = "application_page_active_tab";
    public static final String ACTIVE_VULN_TAB = "active_vuln_tab";
    public static final String SCAN_TAB = "scan_tab";
    public static final String FILE_TAB = "file_tab";
    public static final String SCAN_AGENT_TASK_TAB = "scan_agent_task_tab";
    public static final String SCHEDULED_SCAN_TAB = "scheduled_scan_tab";
    public static final String CLOSED_VULN_TAB = "closed_vuln_tab";
    public static final String FALSE_POSITIVE_TAB = "false_positive_tab";

	private ControllerUtils() {
		// Nobody can instantiate this class
	}
	
	public static Object getItem(HttpServletRequest request, String key) {
		return getAttribute(request, key);
	}

	public static Object getErrorMessage(HttpServletRequest request) {
		return getAttribute(request, ERROR_MESSAGE);
	}
	
	public static Object getSuccessMessage(HttpServletRequest request) {
		return getAttribute(request, SUCCESS_MESSAGE);
	}
	
	public static void addItem(HttpServletRequest request, String key, Object item) {
		addMessage(request, key, item);
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
	
	private static void addMessage(HttpServletRequest request, String key, Object message) {
		if (request == null || message == null) {
			return;
		}
		
		if (request.getSession() != null) {
			request.getSession().setAttribute(key, message);
		}
	}

    public static void setActiveTab(HttpServletRequest request, String activeTab) {
        addMessage(request, ACTIVE_TAB, activeTab);
    }

    public static String getActiveTab(HttpServletRequest request) {
        Object activeTab = getAttribute(request, ACTIVE_TAB);
        if (activeTab != null)
            return activeTab.toString();
        else return null;
    }
}
