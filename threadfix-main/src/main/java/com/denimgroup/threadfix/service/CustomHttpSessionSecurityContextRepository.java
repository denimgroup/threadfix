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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.collections.buffer.CircularFifoBuffer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 4/24/15.
 */
public class CustomHttpSessionSecurityContextRepository
        extends HttpSessionSecurityContextRepository
        implements SecurityContextHolder {

    private Map<Integer, SecurityContext> contextMap = map();
    CircularFifoBuffer seenIds = new CircularFifoBuffer(200);

    private static final SanitizedLogger LOG = new SanitizedLogger(CustomHttpSessionSecurityContextRepository.class);

    @Autowired
    UserService userService;

    public SecurityContext getSecurityContext(Integer id) {
        return contextMap.get(id);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        super.saveContext(context, request, response);

        if (context.getAuthentication() == null ||
                seenIds.contains(context.getAuthentication().hashCode())) {
            return;
        }

        Authentication authentication = context.getAuthentication();
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken principal = (UsernamePasswordAuthenticationToken) authentication;

            Object threadfixPrincipal = principal.getPrincipal();

            if (threadfixPrincipal instanceof ThreadFixUserDetails) {
                Integer userId = ((ThreadFixUserDetails) threadfixPrincipal).getUserId();
                if (userId == 0) {
                    // LDAP user
                    return;
                }
                User user = userService.loadUser(userId);
                if (user == null) {
                    LOG.error("Unable to look up user");
                    return;
                }
                LOG.debug("Adding SecurityContext for user " + user.getName());
                contextMap.put(user.getId(), context);
                seenIds.add(context.getAuthentication().hashCode());
            }
        }
    }
}
