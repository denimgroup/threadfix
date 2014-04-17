////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.service.util;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.ObjectWriter;
import org.codehaus.jackson.map.SerializationConfig;

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
    public static final int NUMBER_ITEM_PER_PAGE = 100;

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

    public static <T> ObjectWriter getObjectWriter(Class<T> targetClass) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationConfig.Feature.DEFAULT_VIEW_INCLUSION, false);

        return mapper.writerWithView(targetClass);
    }
}
