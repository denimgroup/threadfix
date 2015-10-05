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
package com.denimgroup.threadfix.service.eventmodel.aspect;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.EventBuilder;
import com.denimgroup.threadfix.service.ExceptionLogService;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Aspect
@Component
public class ApplicationEventTrackingAspect extends EventTrackingAspect {

    protected SanitizedLogger log = new SanitizedLogger(ApplicationEventTrackingAspect.class);

    @Autowired
    private ExceptionLogService exceptionLogService;

    @Around("execution(* com.denimgroup.threadfix.service.ApplicationService.storeApplication(..)) && args(application, eventAction)")
    public Object emitStoreApplicationEvent(ProceedingJoinPoint joinPoint, Application application, EventAction eventAction) throws Throwable {
        Object proceed = joinPoint.proceed();
        try {
            if ((eventAction == EventAction.APPLICATION_CREATE) || (eventAction == EventAction.APPLICATION_EDIT)) {
                Event event = generateStoreApplicationEvent(application, eventAction);
                publishEventTrackingEvent(event);
            }
        } catch (Exception e) {
            log.error("Error while logging Event: " + eventAction + ", logging to database (visible under Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
        return proceed;
    }

    protected Event generateStoreApplicationEvent(Application application, EventAction eventAction) {
        Event event = new EventBuilder()
                .setUser(userService.getCurrentUser())
                .setEventAction(eventAction)
                .setApplication(application)
                .generateEvent();
        eventService.saveOrUpdate(event);
        return event;
    }

    @Around("execution(* com.denimgroup.threadfix.service.ScanMergeService.saveRemoteScanAndRun(..)) && args(channelId, fileNames, originalFileNames)")
    public Object processSaveRemoteScanAndRunEvent(ProceedingJoinPoint joinPoint, Integer channelId, List<String> fileNames, List<String> originalFileNames) throws Throwable {
        Object proceed = joinPoint.proceed();
        for (String fileName : fileNames) {
            emitUploadApplicationScanEvent((Scan)proceed);
        }
        return proceed;
    }

    @Around("execution(* com.denimgroup.threadfix.service.ScanMergeService.processRemoteScan(..)) && args(scan)")
    public Object processProcessRemoteScanEvent(ProceedingJoinPoint joinPoint, Scan scan) throws Throwable {
        Object proceed = joinPoint.proceed();
        emitUploadApplicationScanEvent((Scan)proceed);
        return proceed;
    }

    @Around("execution(* com.denimgroup.threadfix.service.ScanMergeService.processScan(..)) && args(channelId, fileNames, originalFileNames, statusId, userName)")
    public Object processProcessScanEvent(ProceedingJoinPoint joinPoint, Integer channelId, List<String> fileNames, List<String> originalFileNames, Integer statusId, String userName) throws Throwable {
        Object proceed = joinPoint.proceed();
        emitUploadApplicationScanEvent((Scan)proceed);
        return proceed;
    }

    public void emitUploadApplicationScanEvent(Scan scan) throws Throwable {
        try {
            Event event = generateUploadScanEvent(scan);
            publishEventTrackingEvent(event);
        } catch (Exception e) {
            log.error("Error while logging Event: " + EventAction.APPLICATION_SCAN_UPLOADED + ", logging to database (visible under Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
    }

    protected Event generateUploadScanEvent(Scan scan) {
        Event event = new EventBuilder()
                .setUser(userService.getCurrentUser())
                .setEventAction(EventAction.APPLICATION_SCAN_UPLOADED)
                .setApplication(scan.getApplication())
                .setScan(scan)
                .setDetail(eventService.buildUploadScanString(scan))
                .generateEvent();
        eventService.saveOrUpdate(event);
        return event;
    }

    @Around("execution(* com.denimgroup.threadfix.data.dao.hibernate.HibernateScanDao.deleteFindingsAndScan(com.denimgroup.threadfix.data.entities.Scan)) && args(scan)")
    public void updateEventForScanDeletionAndEmitDeleteApplicationScanEvent(ProceedingJoinPoint joinPoint, Scan scan) throws Throwable {
        Application application = scan.getApplication();
        String eventDescription = eventService.buildDeleteScanString(scan);
        Integer scanId = scan.getId();

        for (Finding finding : scan.getFindings()) {
            for (Event event: eventService.loadAllByFinding(finding)) {
                event.setFinding(null);
                eventService.saveOrUpdate(event);
            }
        }

        for (Event event: eventService.loadAllByScan(scan)) {
            event.setDeletedScanId(scanId);
            event.setScan(null);
            scan.getEvents().remove(event);
            eventService.saveOrUpdate(event);
        }
        scanService.storeScan(scan);

        joinPoint.proceed();
        try {
            Event event = generateDeleteScanEvent(application, eventDescription, scanId);
            publishEventTrackingEvent(event);
        } catch (Exception e) {
            log.error("Error while logging Event: " + EventAction.APPLICATION_SCAN_DELETED + ", logging to database (visible under Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
    }

    protected Event generateDeleteScanEvent(Application application, String scanDescription, Integer scanId) {
        Event event = new EventBuilder()
                .setUser(userService.getCurrentUser())
                .setEventAction(EventAction.APPLICATION_SCAN_DELETED)
                .setApplication(application)
                .setDetail(scanDescription)
                .setDeletedScanId(scanId)
                .generateEvent();
        eventService.saveOrUpdate(event);
        return event;
    }
}
