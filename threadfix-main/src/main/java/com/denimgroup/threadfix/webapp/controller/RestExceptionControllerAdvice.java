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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.ExceptionLog;
import com.denimgroup.threadfix.exception.RestException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ExceptionLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

import org.springframework.security.access.AccessDeniedException;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;

/**
 * Created by mac on 7/3/14.
 */
@ControllerAdvice
public class RestExceptionControllerAdvice {

    @Autowired
    private ExceptionLogService exceptionLogService;

    private static final SanitizedLogger log = new SanitizedLogger(HandlerExceptionResolver.class);

    @ResponseStatus(HttpStatus.OK)
    @ExceptionHandler(value = RestException.class)
    public @ResponseBody RestResponse<String> resolveRestException(Exception ex) {

        ExceptionLog exceptionLog = new ExceptionLog(ex);

        exceptionLogService.storeExceptionLog(exceptionLog);

        log.error("Uncaught exception - logging with ID " + exceptionLog.getUUID() + ".");

        assert ex instanceof RestException;

        return failure(((RestException) ex).getResponseString());
    }

    @ResponseStatus(HttpStatus.OK)
    @ExceptionHandler(value = Exception.class)
    public ModelAndView resolveException(Exception ex) {

        // This should be handled by the other method.
        assert !(ex instanceof RestException) :
                "ControllerAdvice received a RestException in its generic Exception handler";

        assert !(ex instanceof AccessDeniedException) :
                "ControllerAdvice received a AccessDeniedException in its generic Exception handler";

        ExceptionLog exceptionLog = new ExceptionLog(ex);

        exceptionLogService.storeExceptionLog(exceptionLog);

        log.error("Uncaught exception - logging with ID " + exceptionLog.getUUID() + ".");

        ModelAndView mav = new ModelAndView("exception", "uuid", exceptionLog.getUUID());
        mav.addObject("logId", exceptionLog.getId());
        return mav;
    }

    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    @ExceptionHandler(value = AccessDeniedException.class)
    public ModelAndView handleAccessDeniedException() {
        return new ModelAndView("403");
    }

}
