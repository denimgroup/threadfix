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

import com.denimgroup.threadfix.data.entities.VulnerabilityComment;
import com.denimgroup.threadfix.service.eventmodel.event.CommentSubmissionEvent;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Component;

/**
 * Created by mac on 11/6/14.
 */
@Aspect
@Component
public class CommentSubmissionAspect implements ApplicationEventPublisherAware {

    ApplicationEventPublisher eventPublisher;

    @Around("execution(* com.denimgroup.threadfix.service.VulnerabilityCommentService.addCommentToVuln(..))")
    public Object emitEvent(ProceedingJoinPoint joinPoint) throws Throwable {
        VulnerabilityComment comment = (VulnerabilityComment) joinPoint.getArgs()[0];
        Integer vulnerabilityId = (Integer) joinPoint.getArgs()[1];
        Object proceed = joinPoint.proceed();
        eventPublisher.publishEvent(new CommentSubmissionEvent(comment, vulnerabilityId));
        return proceed;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        eventPublisher = applicationEventPublisher;
    }

}
