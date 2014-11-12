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

import com.denimgroup.threadfix.data.interfaces.ProjectMetadataSource;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.eventmodel.event.DefectTrackerProjectMetadataEvent;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Component;

/**
 * Created by mac on 11/11/14.
 */
@Aspect
@Component
public class DefectTrackerFormPopulationAspect implements ApplicationEventPublisherAware {

    ApplicationEventPublisher eventPublisher;

    private static final SanitizedLogger LOG = new SanitizedLogger(DefectTrackerFormPopulationAspect.class);

    @Around("execution(* com.denimgroup.threadfix.service.DefectTrackerService.getProjectMetadata(..))")
    public Object emitEvent(ProceedingJoinPoint joinPoint) throws Throwable {
        LOG.debug("Emitting getProjectMetadata event.");

        ProjectMetadataSource metadataSource = (ProjectMetadataSource) joinPoint.getArgs()[0];

        AbstractDefectTracker tracker = null;

        if (metadataSource instanceof AbstractDefectTracker) {
            tracker = (AbstractDefectTracker) metadataSource;
            LOG.debug("Got AbstractDefectTracker from metadataSource");
        } else {
            LOG.error("MetadataSource wasn't an AbstractDefectTracker. This shouldn't happen.");
            assert false : "Shouldn't be here, fix your code";
        }

        Object proceed = joinPoint.proceed();
        eventPublisher.publishEvent(new DefectTrackerProjectMetadataEvent(tracker, (ProjectMetadata) proceed));
        return proceed;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        eventPublisher = applicationEventPublisher;
    }
}