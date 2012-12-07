////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.ExceptionLog;
import com.denimgroup.threadfix.service.ExceptionLogService;
import com.denimgroup.threadfix.service.SanitizedLogger;

/**
 * TODO decide if 404 is the right option for ResourceNotFoundException
 * TODO decide whether or not to include more information for ResourceNotFoundException
 * @author mcollins
 *
 */
public class HandlerExceptionResolverBean implements HandlerExceptionResolver {

	@Autowired
	private ExceptionLogService exceptionLogService;
	
	private final SanitizedLogger log = new SanitizedLogger(HandlerExceptionResolver.class);
	
	@Override
	public ModelAndView resolveException(HttpServletRequest request,
			HttpServletResponse response, Object handler, Exception ex) {
		
		if (ex instanceof ResourceNotFoundException) {
			
			return new ModelAndView("resourceNotFound");
			
		} else if (ex instanceof AccessDeniedException) {
			
			return new ModelAndView("403");
			
		} else {
			
			ExceptionLog exceptionLog = new ExceptionLog(ex);
			
			exceptionLogService.storeExceptionLog(exceptionLog);
			
			log.error("Uncaught exception - logging with ID " + exceptionLog.getUUID() + ".");
				
			return new ModelAndView("exception", "id", exceptionLog.getUUID());
		}
	}
}
