////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.ExceptionLog;
import com.denimgroup.threadfix.exception.AuthenticationRestException;
import com.denimgroup.threadfix.exception.RestException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ExceptionLogService;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.mysql.jdbc.PacketTooBigException;
import org.springframework.beans.TypeMismatchException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.orm.hibernate3.HibernateJdbcException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.ws.client.WebServiceTransportException;

import javax.servlet.http.HttpServletRequest;
import java.text.SimpleDateFormat;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;

/**
 * Created by mac on 7/3/14.
 */
@ControllerAdvice
public class RestExceptionControllerAdvice {

    @Autowired
    private ExceptionLogService exceptionLogService;

    private static final SanitizedLogger log = new SanitizedLogger(RestExceptionControllerAdvice.class);

    private static final SimpleDateFormat format = new SimpleDateFormat("MMM d, y h:mm:ss a");

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(value = RestException.class)
    @ResponseBody
    public RestResponse<String> resolveRestException(RestException ex) {

        ExceptionLog exceptionLog = new ExceptionLog(ex);

        exceptionLogService.storeExceptionLog(exceptionLog);

        log.error("Uncaught exception - logging at " + format.format(exceptionLog.getTime().getTime()) + ".");

        return failure(ex.getResponseString());
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(value = HibernateJdbcException.class)
    @ResponseBody
    public RestResponse<String> resolveException(HibernateJdbcException ex) {

        ExceptionLog exceptionLog = new ExceptionLog(ex);

        exceptionLogService.storeExceptionLog(exceptionLog);

        log.error("Uncaught exception - logging at " + format.format(exceptionLog.getTime().getTime()) + ".");

        if (ex.getRootCause().getClass().equals(PacketTooBigException.class)) {
            return failure("Scan is too large to be handled by your MySQL Server. You can remediate this " +
                    "by increasing the 'max_allowed_packet' size for your MySQL Server instance.");
        }  else {
            return failure(ex.getRootCause().getMessage());
        }
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(value = AuthenticationRestException.class)
    @ResponseBody
    public RestResponse<String> resolveAuthenticationException(AuthenticationRestException ex) {
        return resolveRestException(ex);
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(value = BindException.class)
    @ResponseBody
    public RestResponse<String> resolveBindException(BindException e) {
        ExceptionLog exceptionLog = new ExceptionLog(e);

        exceptionLogService.storeExceptionLog(exceptionLog);

        log.error("Uncaught exception - logging at " + format.format(exceptionLog.getTime().getTime()) + ".");

        return failure(e.getMessage());
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(NoHandlerFoundException.class)
    public ModelAndView handleError404(HttpServletRequest request, Exception e) {

        if (request.getUserPrincipal() == null) {
            return new ModelAndView("redirect:/login.jsp");
        }

        return new ModelAndView("404");
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(value = ResourceNotFoundException.class)
    @ResponseBody
    public ModelAndView handleResourceNotFound(HttpServletRequest request, ResourceNotFoundException e) {
        return handleError404(request, e);
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(TypeMismatchException.class)
    public ModelAndView handleTypeMismatch(HttpServletRequest request, TypeMismatchException e) {
        log.warn("TypeMismatchException at " + request.getRequestURI() + ": " + e.getMessage());
        return handleError404(request, e);
    }

    @ResponseStatus(HttpStatus.OK)
    @ExceptionHandler(value = Exception.class)
    public ModelAndView resolveException(Exception ex) {

        // This should be handled by the other method.
        assert !(ex instanceof RestException) :
                "ControllerAdvice received a RestException in its generic Exception handler";

        assert !(ex instanceof AccessDeniedException) :
                "ControllerAdvice received a AccessDeniedException in its generic Exception handler";

        assert !(ex instanceof WebServiceTransportException) :
                "ControllerAdvice received a WebServiceTransportException in its generic Exception handler";

        ExceptionLog exceptionLog = new ExceptionLog(ex);

        exceptionLogService.storeExceptionLog(exceptionLog);

        log.error("Uncaught exception - logging at " + format.format(exceptionLog.getTime().getTime()) + ".");

        ModelAndView mav = new ModelAndView("exception", "time", format.format(exceptionLog.getTime().getTime()));
        mav.addObject("logId", exceptionLog.getId());
        return mav;
    }

    @ResponseStatus(HttpStatus.OK)
    @ExceptionHandler(value = WebServiceTransportException.class)
    public @ResponseBody RestResponse<String> resolveWebServiceTransportException(WebServiceTransportException ex) {

        ExceptionLog exceptionLog = new ExceptionLog(ex);
        exceptionLogService.storeExceptionLog(exceptionLog);

        log.error("Uncaught exception - logging at " + format.format(exceptionLog.getTime().getTime()) + ".");

        if(ex.getMessage().contains("401")){
            return failure("GRC Credentials not valid.");
        } else if(ex.getMessage().contains("403")){
            return failure("Cannot reach GRC service.");
        } else {
            return failure(ex.getMessage());
        }
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(value = AccessDeniedException.class)
    public ModelAndView handleAccessDeniedException() {
        return new ModelAndView("403");
    }

}
