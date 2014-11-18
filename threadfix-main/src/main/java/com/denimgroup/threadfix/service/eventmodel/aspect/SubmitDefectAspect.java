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
package com.denimgroup.threadfix.service.eventmodel.aspect;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.eventmodel.event.PreDefectSubmissionEvent;
import com.denimgroup.threadfix.viewmodel.DefectMetadata;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

/**
 * Created by mac on 11/12/14.
 *
 */
@Aspect
@Component
class SubmitDefectAspect implements ApplicationEventPublisherAware {

    ApplicationEventPublisher eventPublisher;

    private static final SanitizedLogger LOG = new SanitizedLogger(DefectTrackerFormPopulationAspect.class);

    @Around("execution(* com.denimgroup.threadfix.service.DefectSubmissionServiceImpl.submitDefect(..))")
    public Object emitEvent(ProceedingJoinPoint joinPoint) throws Throwable {
        LOG.debug("Emitting getProjectMetadata event.");

        Object[] args = joinPoint.getArgs();
        assert args.length == 3 :
                "Length of join point arguments wasn't 3: " + Arrays.toString(args);

        AbstractDefectTracker tracker = getAs(args[0], AbstractDefectTracker.class);
        List vulns = getAs(args[1], List.class);
        DefectMetadata metadata = getAs(args[2], DefectMetadata.class);

        eventPublisher.publishEvent(new PreDefectSubmissionEvent(tracker, vulns, metadata));

        return joinPoint.proceed(new Object[] { tracker, vulns, metadata });
    }

    @SuppressWarnings("unchecked") // we check with Class.isInstance
    private <C> C getAs(Object input, Class<C> classReference) {
        if (classReference.isInstance(input)) {
            return (C) input;
        } else {
            throw new IllegalArgumentException(input + " wasn't a " + classReference.getSimpleName());
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        eventPublisher = applicationEventPublisher;
    }
}
