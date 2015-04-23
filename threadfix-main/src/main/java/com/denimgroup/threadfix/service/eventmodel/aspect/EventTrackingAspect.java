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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Event;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.EventBuilder;
import com.denimgroup.threadfix.service.EventService;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.service.eventmodel.event.EventTrackingEvent;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class EventTrackingAspect implements ApplicationEventPublisherAware {

    private final SanitizedLogger log = new SanitizedLogger(EventTrackingAspect.class);

    ApplicationEventPublisher eventPublisher;

    @Autowired
    EventService eventService;

    @Autowired
    UserService userService;

    @Around("execution(* com.denimgroup.threadfix.service.ApplicationService.storeApplication(..)) && args(application, eventAction)")
    public Object emitStoreApplicationEvent(ProceedingJoinPoint joinPoint, Application application, EventAction eventAction) throws Throwable {
        Object proceed = joinPoint.proceed();
        try {
            if ((eventAction == EventAction.APPLICATION_CREATE) || (eventAction == EventAction.APPLICATION_EDIT)) {
                Event event = generateStoreApplicationEvent(application, eventAction);
                publishEventTrackingEvent(event);
            }
        } catch (Exception e) {
            log.error("Error while logging Event: " + eventAction, e);
        } finally {
            return proceed;
        }
    }

    @Pointcut("execution(* com.denimgroup.threadfix.service.ScanMergeService.saveRemoteScanAndRun(Integer, String))")
    private void saveRemoteScanAndRun() {}

    @Pointcut("execution(* com.denimgroup.threadfix.service.ScanMergeService.processScan(Integer, String, ..))")
    private void processScan() {}

    @Pointcut("saveRemoteScanAndRun() || processScan()")
    private void processScanFile() {}

    @Around("processScanFile() && args(channelId, fileName)")
    public Object emitUploadApplicationScanEvent(ProceedingJoinPoint joinPoint, Integer channelId, String fileName) throws Throwable {
        Object proceed = joinPoint.proceed();
        try {
            Scan scan = (Scan) proceed;
            Event event = generateUploadScanEvent(scan);
            publishEventTrackingEvent(event);
        } catch (Exception e) {
            log.error("Error while logging Event: " + EventAction.APPLICATION_SCAN_UPLOADED, e);
        } finally {
            return proceed;
        }
    }

    protected Event generateStoreApplicationEvent(Application application, EventAction eventAction) {
        Event event = new EventBuilder()
                .setUser(userService.getCurrentUser())
                .setEventAction(eventAction)
                .setApplication(application)
                .generateEvent();
        eventService.saveEvent(event);
        return event;
    }

    private Event generateUploadScanEvent(Scan scan) {
        Event event = new EventBuilder()
                .setUser(userService.getCurrentUser())
                .setEventAction(EventAction.APPLICATION_SCAN_UPLOADED)
                .setApplication(scan.getApplication())
                .setScan(scan)
                .generateEvent();
        eventService.saveEvent(event);
        return event;
    }

    protected void publishEventTrackingEvent(Event event) {
        eventPublisher.publishEvent(new EventTrackingEvent(event));
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        eventPublisher = applicationEventPublisher;
    }

}
