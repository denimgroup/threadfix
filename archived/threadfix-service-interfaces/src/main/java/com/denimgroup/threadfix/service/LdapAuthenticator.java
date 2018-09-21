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

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class LdapAuthenticator implements AuthenticationProvider, LdapAuthenticatorService {

    protected final SanitizedLogger log = new SanitizedLogger(LdapService.class);

    @Autowired(required = false)
    private LdapService ldapService;

    public LdapAuthenticator() {
    }

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) {
        try {
            log.debug("Attempting to authenticate with LDAP authenticator.");
            return ldapService != null ? ldapService.authenticate(authentication) : null;
        } catch (ThreadFixActiveDirectoryAuthenticationException e) {
            log.debug("Failed LDAP authentication.");
            return null;
        } catch (Exception e) { // this is to prevent bad input
            log.error("Encountered exception. Your LDAP configuration is probably invalid.", e);
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        try {
            return ldapService != null && ldapService.supports(authentication);
        } catch (ThreadFixActiveDirectoryAuthenticationException e) {
            log.debug("Failed LDAP authentication.");
            return false;
        } catch (Exception e) { // this is to prevent bad input
            log.error("Encountered exception. Your LDAP configuration is probably invalid.", e);
            return false;
        }
    }

}