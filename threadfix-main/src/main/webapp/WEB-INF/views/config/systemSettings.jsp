<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>System Settings</title>
</head>

<body id="config" ng-init="successMessage = '<c:out value="${ successMessage }"/>'">
	<h2>System Settings</h2>

    <%@ include file="../angular-init.jspf" %>

    <div ng-show="successMessage" class="alert alert-success">
        <button class="close" ng-click="successMessage = undefined" type="button">&times;</button>
        {{ successMessage }}
    </div>
	
	<spring:url value="" var="emptyUrl"/>
	<form:form modelAttribute="defaultConfiguration" name="formEditUser" action="${ fn:escapeXml(emptyUrl) }">
        <div class="panel panel-default">
            <div id="defaultPermissionsPanel" class="panel-heading pointer" style="width:200px" ng-click="editDefaultPermissions = !editDefaultPermissions">
                <h3 class="panel-title">
                    <span ng-hide="editDefaultPermissions" class="icon icon-chevron-right"></span>
                    <span ng-show="editDefaultPermissions" class="icon icon-chevron-down"></span>
                    Default LDAP Role
                </h3>
            </div>
            <div class="panel-body" ng-show="editDefaultPermissions">
                <table class="dataTable">
                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_ROLES">
                        <tr>
                            <td>
                                Default role enabled for LDAP users
                            </td>
                            <td class="inputValue" style="text-align: left;" ng-init="globalGroupEnabled = <c:out value="${ defaultConfiguration.globalGroupEnabled }"/>">
                                <form:checkbox id="globalGroupEnabledCheckbox" path="globalGroupEnabled" ng-model="globalGroupEnabled"/>
                            </td>
                            <td class="inputValue">
                                <form:select ng-disabled="!globalGroupEnabled" id="roleSelect" path="defaultRoleId">
                                    <form:option value="0" label="Read Access" />
                                    <form:options items="${ roleList }" itemValue="id" itemLabel="displayName" />
                                </form:select>
                            </td>
                            <td style="border: 0 solid black; background-color: white; padding-left: 5px">
                                <a class="btn" popover="When LDAP users log in, ThreadFix can assign them a default role. If no role is selected here, the user will be unable to access any data in ThreadFix. To configure per-team and per-application permissions for an LDAP user, create a ThreadFix user with the same username.">?</a>
                                <form:errors id="globalGroupEnabledErrors" path="globalGroupEnabled" cssClass="errors" />
                            </td>
                        </tr>
                    </security:authorize>
                </table>
            </div>
        </div>

        <c:if test="${ isEnterprise }">
            <div class="panel panel-default">
                <div id="ldapSettingsPanel" class="panel-heading pointer" style="width:150px" ng-click="editLdapSettings = !editLdapSettings">
                    <h3 class="panel-title">
                        <span ng-hide="editLdapSettings" class="icon icon-chevron-right"></span>
                        <span ng-show="editLdapSettings" class="icon icon-chevron-down"></span>
                        LDAP Settings
                    </h3>
                </div>
                <div class="panel-body" ng-show="editLdapSettings">
                    <table>
                        <tr>
                            <td style="width:150px" class="no-color">LDAP Search Base</td>
                            <td class="no-color">
                                <form:input id="activeDirectoryBase" path="activeDirectoryBase" cssClass="focus" size="60" maxlength="255" value="${ defaultConfiguration.activeDirectoryBase }"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="activeDirectoryBase" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">LDAP User DN</td>
                            <td class="no-color">
                                <form:input id="activeDirectoryUsername" path="activeDirectoryUsername" cssClass="focus" size="60" maxlength="255" value="${ defaultConfiguration.activeDirectoryUsername }"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="activeDirectoryUsername" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">LDAP Password</td>
                            <td class="no-color">
                                <form:input id="activeDirectoryCredentials" path="activeDirectoryCredentials" cssClass="focus" size="60" maxlength="255" value="${ defaultConfiguration.activeDirectoryCredentials }"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="activeDirectoryCredentials" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">LDAP URL</td>
                            <td class="no-color">
                                <form:input id="activeDirectoryURL" path="activeDirectoryURL" cssClass="focus" size="60" maxlength="255" value="${ defaultConfiguration.activeDirectoryURL }"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="activeDirectoryURL" cssClass="errors" />
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
            <div class="panel panel-default">
                <div id="proxySettingsPanel" class="panel-heading pointer" style="width:150px" ng-click="configureProxySettings = !configureProxySettings">
                    <h3 class="panel-title">
                        <span ng-hide="configureProxySettings" class="icon icon-chevron-right"></span>
                        <span ng-show="configureProxySettings" class="icon icon-chevron-down"></span>
                        Proxy Settings
                    </h3>
                </div>
                <div class="panel-body" ng-show="configureProxySettings">
                    <table class="even-sized-rows">
                        <tr>
                            <td style="width:150px" class="no-color">Proxy Host</td>
                            <td class="no-color">
                                <form:input id="proxyHost" path="proxyHost" cssClass="focus" size="60" maxlength="255" value="${ defaultConfiguration.proxyHost }"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px" >
                                <form:errors path="activeDirectoryUsername" id="proxyHostErrors" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">Proxy Port</td>
                            <td class="no-color">
                                <form:input id="proxyPort" path="proxyPort" cssClass="focus" size="60" maxlength="255" value="${ defaultConfiguration.proxyPort }"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="proxyPort" id="proxyPortErrors" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td>Use Proxy Credentials</td>
                            <td ng-init="shouldUseProxyCredentials = <c:out value="${ defaultConfiguration.shouldUseProxyCredentials }"/>">
                                <form:checkbox path="shouldUseProxyCredentials" ng-model="shouldUseProxyCredentials" value="${ defaultConfiguration.shouldUseProxyCredentials }"/>
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">Proxy Username</td>
                            <td class="no-color">
                                <c:if test="${ empty defaultConfiguration.proxyUsernameEncrypted }">
                                    <form:input ng-disabled="!shouldUseProxyCredentials"
                                                id="proxyUsername"
                                                path="proxyUsername"
                                                cssClass="focus"
                                                size="60"
                                                maxlength="255"
                                                value="${ defaultConfiguration.proxyUsername }"/>
                                </c:if>
                                <c:if test="${ not empty defaultConfiguration.proxyUsernameEncrypted }">
                                    <form:input ng-disabled="!shouldUseProxyCredentials"
                                                id="proxyUsername"
                                                path="proxyUsername"
                                                cssClass="focus"
                                                size="60"
                                                maxlength="255"
                                                value=""
                                                placeholder="Use configured username"/>
                                </c:if>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="proxyUsername" id="proxyUsernameErrors" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">Proxy Password</td>
                            <td class="no-color">
                                <c:if test="${ empty defaultConfiguration.proxyPasswordEncrypted }">
                                    <form:input ng-disabled="!shouldUseProxyCredentials"
                                                id="proxyPassword"
                                                path="proxyPassword"
                                                cssClass="focus"
                                                size="60"
                                                maxlength="255"
                                                value="${ defaultConfiguration.proxyPassword }"/>
                                </c:if>
                                <c:if test="${ not empty defaultConfiguration.proxyPasswordEncrypted }">
                                    <form:input ng-disabled="!shouldUseProxyCredentials"
                                                id="proxyPassword"
                                                path="proxyPassword"
                                                cssClass="focus"
                                                size="60"
                                                maxlength="255"
                                                value=""
                                                placeholder="Use configured password"/>
                                </c:if>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="proxyPassword" id="proxyPasswordErrors" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td>Qualys</td>
                            <td><form:checkbox path="shouldProxyQualys" value="${ defaultConfiguration.shouldProxyQualys }"/></td>
                        </tr>
                        <tr>
                            <td>Veracode</td>
                            <td><form:checkbox path="shouldProxyVeracode" value="${ defaultConfiguration.shouldProxyVeracode }"/></td>
                        </tr>
                        <tr>
                            <td>WhiteHat Sentinel</td>
                            <td><form:checkbox path="shouldProxyWhiteHat" value="${ defaultConfiguration.shouldProxyWhiteHat }"/></td>
                        </tr>
                        <tr>
                            <td>TFS</td>
                            <td><form:checkbox path="shouldProxyTFS" value="${ defaultConfiguration.shouldProxyTFS }"/></td>
                        </tr>
                        <tr>
                            <td>Bugzilla</td>
                            <td><form:checkbox path="shouldProxyBugzilla" value="${ defaultConfiguration.shouldProxyBugzilla }"/></td>
                        </tr>
                        <tr>
                            <td>Jira</td>
                            <td><form:checkbox path="shouldProxyJira" value="${ defaultConfiguration.shouldProxyJira }"/></td>
                        </tr>
                        <tr>
                            <td>Version One</td>
                            <td><form:checkbox path="shouldProxyVersionOne" value="${ defaultConfiguration.shouldProxyVersionOne }"/></td>
                        </tr>
                        <tr>
                            <td>HP Quality Center</td>
                            <td><form:checkbox path="shouldProxyHPQC" value="${ defaultConfiguration.shouldProxyHPQC }"/></td>
                        </tr>
                        <tr>
                            <td>Trustwave Hailstorm</td>
                            <td><form:checkbox path="shouldProxyTrustwaveHailstorm" value="${ defaultConfiguration.shouldProxyTrustwaveHailstorm }"/></td>
                        </tr>
                    </table>
                </div>
            </div>
        </c:if>

        <div class="panel panel-default">
            <div id="defaultSessionTimeoutPermissionsPanel" class="panel-heading pointer" style="width:200px" ng-click="editSessionTimeoutPermissions = !editSessionTimeoutPermissions">
                <h3 class="panel-title">
                    <span ng-hide="editSessionTimeoutPermissions" class="icon icon-chevron-right"></span>
                    <span ng-show="editSessionTimeoutPermissions" class="icon icon-chevron-down"></span>
                    Session Timeout
                </h3>
            </div>
            <div class="panel-body" ng-show="editSessionTimeoutPermissions">
                <table>
                    <tr>
                        <td style="width:150px" class="no-color">Session Timeout</td>
                        <td class="no-color">
                            <form:input id="sessionTimeout" type="number" max="30" min="1" path="sessionTimeout" placeholder="(in minutes)" cssClass="focus" size="60" maxlength="255" value="${ defaultConfiguration.sessionTimeout }"/>
                        </td>
                        <td class="no-color" style="padding-left: 5px">
                            <form:errors path="sessionTimeout" cssClass="errors" />
                        </td>
                    </tr>
                </table>
            </div>
        </div>

		<br/>
		<button class="btn btn-primary" type="submit" id="updateDefaultsButton">Save Changes</button>
	</form:form>
</body>
