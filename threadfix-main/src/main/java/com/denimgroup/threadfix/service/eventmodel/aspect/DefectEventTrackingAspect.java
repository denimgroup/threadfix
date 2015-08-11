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
import com.denimgroup.threadfix.service.*;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Aspect
@Component
public class DefectEventTrackingAspect extends EventTrackingAspect {

    protected SanitizedLogger log = new SanitizedLogger(DefectEventTrackingAspect.class);

    @Autowired
    private ExceptionLogService exceptionLogService;
    @Autowired
    private ApplicationService applicationService;

    @Around("execution(* com.denimgroup.threadfix.service.DefectService.createDefect(..))")
    public Object emitSubmitDefectEvent(ProceedingJoinPoint joinPoint) throws Throwable {
        Object proceed = joinPoint.proceed();
        try {
            Map<String, Object> map = (Map<String, Object>) proceed;
            if (map.get(DefectService.DEFECT) instanceof Defect) {
                Defect newDefect = (Defect)map.get(DefectService.DEFECT);
                Event event = generateSubmitDefectEvent(newDefect);
                publishEventTrackingEvent(event);
            }
        } catch (Exception e) {
            log.error("Error while logging Event: " + EventAction.DEFECT_SUBMIT + ", logging to database (visible under View Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
        return proceed;
    }

    @Around("execution(* com.denimgroup.threadfix.service.DefectService.updateVulnsFromDefectTracker(..)) && args(applicationId, userId)")
    public Object emitUpdateDefectStatusEvent(ProceedingJoinPoint joinPoint, Integer applicationId, Integer userId) throws Throwable {
        Map<Integer, String> vulnerabilityDefectStatuses = new HashMap<Integer, String>();
        Map<Integer, Boolean> vulnerabilityDefectClosed = new HashMap<Integer, Boolean>();
        boolean errorLoggingEvent = false;
        Application application = null;
        try {
            application = applicationService.loadApplication(applicationId);
            for (Vulnerability vuln : application.getVulnerabilities()) {
                Defect defect = vuln.getDefect();
                if (defect != null) {
                    vulnerabilityDefectStatuses.put(vuln.getId(), defect.getStatus());
                    vulnerabilityDefectClosed.put(vuln.getId(), defect.isClosed());
                }
            }
        } catch (Exception e) {
            errorLoggingEvent = true;
            log.error("Error while logging Event: " + EventAction.DEFECT_STATUS_UPDATED + ", logging to database (visible under View Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
        Object proceed = joinPoint.proceed();
        try {
            if (!errorLoggingEvent && (application != null)) {
                for (Vulnerability vuln : application.getVulnerabilities()) {
                    Defect defect = vuln.getDefect();
                    if (defect != null) {
                        User user = null;
                        try {
                            user = userService.loadUser(userId);
                        } catch (Exception e) {}

                        String newStatus = defect.getStatus();
                        String oldStatus = vulnerabilityDefectStatuses.get(vuln.getId());
                        if (!newStatus.equals(oldStatus)) {
                            Event event = generateUpdateDefectStatusEvent(defect, user);
                            publishEventTrackingEvent(event);
                        }

                        Boolean isClosed = defect.isClosed();
                        Boolean wasClosed = vulnerabilityDefectClosed.get(vuln.getId());
                        if (isClosed && !wasClosed) {
                            Event event = generateCloseDefectEvent(defect, user);
                            publishEventTrackingEvent(event);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error while logging Event: " + EventAction.DEFECT_STATUS_UPDATED + ", logging to database (visible under View Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
        return proceed;
    }

    @Around("execution(* com.denimgroup.threadfix.service.ScanMergeService.saveRemoteScanAndRun(..)) && args(channelId, fileNames, originalFileNames)")
    public Object processSaveRemoteScanAndRunEvent(ProceedingJoinPoint joinPoint, Integer channelId, List<String> fileNames, List<String> originalFileNames) throws Throwable {
        return emitUploadApplicationScanEvent(joinPoint);
    }

    @Around("execution(* com.denimgroup.threadfix.service.ScanMergeService.processScan(..)) && args(channelId, fileNames, originalFileNames, statusId, userName)")
    public Object processProcessScanEvent(ProceedingJoinPoint joinPoint, Integer channelId, List<String> fileNames, List<String> originalFileNames, Integer statusId, String userName) throws Throwable {
        return emitUploadApplicationScanEvent(joinPoint);
    }

    public Object emitUploadApplicationScanEvent(ProceedingJoinPoint joinPoint) throws Throwable {
        Object proceed = joinPoint.proceed();
        try {
            Scan scan = (Scan) proceed;
            Set<Finding> findings = new HashSet<Finding>();
            findings.addAll(scan.getFindings());
            List<ScanRepeatFindingMap> scanRepeatFindingMaps = scan.getScanRepeatFindingMaps();
            if (scanRepeatFindingMaps != null) {
                for (ScanRepeatFindingMap scanRepeatFindingMap : scanRepeatFindingMaps) {
                    findings.add(scanRepeatFindingMap.getFinding());
                }
            }

            for (Finding finding : findings) {
                Vulnerability vulnerability = finding.getVulnerability();
                if (vulnerability != null) {
                    Defect defect = vulnerability.getDefect();
                    if ((defect != null) && (defect.isClosed())) {
                        Event event = generateDefectAppearedAfterClosedEvent(defect, scan);
                        publishEventTrackingEvent(event);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error while logging Event: " + EventAction.DEFECT_APPEARED_AFTER_CLOSED + ", logging to database (visible under View Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
        return proceed;
    }

    protected Event generateSubmitDefectEvent(Defect defect) {
        return generateDefectEvent(EventAction.DEFECT_SUBMIT, defect, null, userService.getCurrentUser());
    }

    protected Event generateUpdateDefectStatusEvent(Defect defect, User user) {
        return generateDefectEvent(EventAction.DEFECT_STATUS_UPDATED, defect, null, user);
    }

    protected Event generateCloseDefectEvent(Defect defect, User user) {
        return generateDefectEvent(EventAction.DEFECT_CLOSED, defect, null, user);
    }

    protected Event generateDefectAppearedAfterClosedEvent(Defect defect, Scan scan) {
        return generateDefectEvent(EventAction.DEFECT_APPEARED_AFTER_CLOSED, defect, scan, userService.getCurrentUser());
    }

    protected Event generateDefectEvent(EventAction eventAction, Defect defect, Scan scan, User user) {
        EventBuilder eventBuilder = new EventBuilder();
        eventBuilder.setUser(user);
        eventBuilder.setEventAction(eventAction);
        eventBuilder.setDefect(defect);
        eventBuilder.setApplication(defect.getApplication());
        eventBuilder.setScan(scan);
        eventBuilder.setStatus(defect.getStatus());
        Event event = eventBuilder.generateEvent();
        eventService.saveOrUpdate(event);
        return event;
    }

    @Around("execution(* com.denimgroup.threadfix.data.dao.hibernate.HibernateDefectDao.delete(..)) && args(defect)")
    public void updateEventForDefectDeletion(ProceedingJoinPoint joinPoint, Defect defect) throws Throwable {
        List<Event> eventList = eventService.loadAllByDefect(defect);

        for (Event event: eventList) {
            event.setDefect(null);
            eventService.saveOrUpdate(event);
        }
        joinPoint.proceed();
    }
}
