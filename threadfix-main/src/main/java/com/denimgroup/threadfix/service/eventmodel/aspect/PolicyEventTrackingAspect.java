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

import java.util.List;

@Aspect
@Component
public class PolicyEventTrackingAspect extends EventTrackingAspect {

    protected SanitizedLogger log = new SanitizedLogger(PolicyEventTrackingAspect.class);

    @Autowired
    private ExceptionLogService exceptionLogService;
    @Autowired
    private ApplicationService applicationService;

    @Around("execution(* com.denimgroup.threadfix.service.PolicyStatusService.runStatusCheck(..)) && args(policy)")
    public Object emitPolicyStatusCheckEvents(ProceedingJoinPoint joinPoint, Policy policy) throws Throwable {
        Object proceed = joinPoint.proceed();
        try {
            List<PolicyStatus> policyStatuses = policy.getPolicyStatuses();
            emitPolicyStatusCheckEvents(policyStatuses);
        } catch (Exception e) {
            log.error("Error while logging Policy Status Check Events, logging to database (visible under Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
        return proceed;
    }

    @Around("execution(* com.denimgroup.threadfix.service.PolicyStatusService.runStatusCheck(..)) && args(applicationId)")
    public Object emitPolicyStatusCheckEvents(ProceedingJoinPoint joinPoint, int applicationId) throws Throwable {
        Object proceed = joinPoint.proceed();
        try {
            Application application = applicationService.loadApplication(applicationId);
            if (application != null) {
                List<PolicyStatus> policyStatuses = application.getPolicyStatuses();
                emitPolicyStatusCheckEvents(policyStatuses);
            }
        } catch (Exception e) {
            log.error("Error while logging Policy Status Check Events, logging to database (visible under Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
        return proceed;
    }

    protected void emitPolicyStatusCheckEvents(List<PolicyStatus> policyStatuses) throws Throwable {
        for (PolicyStatus policyStatus : policyStatuses) {
            if (policyStatus.hasStatusChanged()) {
                emitPolicyStatusUpdateEvent(policyStatus);
            }
        }
    }

    @Around("execution(* com.denimgroup.threadfix.service.PolicyStatusService.addStatus(..)) && args(policy, application)")
    public Object emitPolicyAddStatusEvent(ProceedingJoinPoint joinPoint,
                                                          Policy policy, Application application) throws Throwable {
        Object proceed = joinPoint.proceed();
        try {
            List<PolicyStatus> policyStatuses = policy.getPolicyStatuses();
            for (PolicyStatus policyStatus : policyStatuses) {
                if ((policyStatus.getApplication() != null) && (policyStatus.getApplication().getId() == application.getId())) {
                    emitPolicyStatusUpdateEvent(policyStatus);
                }
            }
        } catch (Exception e) {
            log.error("Error while logging Policy Status Check Events, logging to database (visible under Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
        return proceed;
    }

    protected void emitPolicyStatusUpdateEvent(PolicyStatus policyStatus) throws Throwable {
        EventAction eventAction;
        if (policyStatus.isPassing()) {
            eventAction = EventAction.ACCEPTANCE_CRITERIA_PASSING;
        } else {
            eventAction = EventAction.ACCEPTANCE_CRITERIA_FAILING;
        }
        try {
            Event event = generatePolicyStatusUpdateEvent(policyStatus, eventAction);
            publishEventTrackingEvent(event);
        } catch (Exception e) {
            log.error("Error while logging Event: " + eventAction + ", logging to database (visible under Error Messages)");
            exceptionLogService.storeExceptionLog(new ExceptionLog(e));
        }
    }

    protected Event generatePolicyStatusUpdateEvent(PolicyStatus policyStatus, EventAction eventAction) {
        Event event = new EventBuilder()
                .setUser(userService.getCurrentUser())
                .setEventAction(eventAction)
                .setPolicyStatus(policyStatus)
                .setPolicy(policyStatus.getPolicy())
                .setApplication(policyStatus.getApplication())
                .generateEvent();
        eventService.saveOrUpdate(event);
        return event;
    }

    @Around("execution(* com.denimgroup.threadfix.data.dao.PolicyDao.delete(..)) && args(policy)")
    public void updateEventForPolicyDeletion(ProceedingJoinPoint joinPoint, Policy policy) throws Throwable {
        List<Event> eventList = eventService.loadAllByPolicy(policy);

        for (Event event: eventList) {
            event.setPolicy(null);
            eventService.saveOrUpdate(event);
        }
        joinPoint.proceed();
    }

    @Around("execution(* com.denimgroup.threadfix.data.dao.PolicyStatusDao.delete(..)) && args(policyStatus)")
    public void updateEventForPolicyStatusDeletion(ProceedingJoinPoint joinPoint, PolicyStatus policyStatus) throws Throwable {
        List<Event> eventList = eventService.loadAllByPolicyStatus(policyStatus);

        for (Event event: eventList) {
            event.setPolicyStatus(null);
            eventService.saveOrUpdate(event);
        }
        joinPoint.proceed();
    }
}
