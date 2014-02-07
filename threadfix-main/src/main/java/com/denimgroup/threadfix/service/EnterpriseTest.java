package com.denimgroup.threadfix.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

public class EnterpriseTest extends SpringBeanAutowiringSupport {

    @Autowired(required = false)
    LdapService ldapService;

    @Autowired(required = false)
    PermissionService permissionService;

    public static boolean isEnterprise() {
        EnterpriseTest enterpriseTest = new EnterpriseTest();

        return enterpriseTest.ldapService != null && enterpriseTest.permissionService != null;
    }
}
