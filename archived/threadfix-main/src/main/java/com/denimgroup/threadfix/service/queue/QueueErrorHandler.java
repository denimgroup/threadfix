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
package com.denimgroup.threadfix.service.queue;

import com.denimgroup.threadfix.data.entities.ExceptionLog;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ExceptionLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.ErrorHandler;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import java.text.SimpleDateFormat;

/**
 * Created by mcollins on 6/4/14.
 */
public class QueueErrorHandler extends SpringBeanAutowiringSupport implements ErrorHandler {

    @Autowired
    private ExceptionLogService exceptionLogService;

    private final SanitizedLogger log = new SanitizedLogger(QueueErrorHandler.class);

    private static final SimpleDateFormat format = new SimpleDateFormat("MMM d, y h:mm:ss a");

    @Override
    public void handleError(Throwable throwable) {
        ExceptionLog exceptionLog = new ExceptionLog(throwable);

        exceptionLogService.storeExceptionLog(exceptionLog);

        log.error("Uncaught exception - logging at " + format.format(exceptionLog.getTime().getTime()) + ".");
    }
}
