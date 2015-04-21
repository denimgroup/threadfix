<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>System Settings</title>
    <cbs:cachebustscript src="/scripts/check-ldap-controller.js"/>
</head>

<body id="config" ng-init="successMessage = '<c:out value="${ successMessage }"/>'; showErrors = '<c:out value="${ errors.size() > 0 }"/>'">
    <h2>System Settings</h2>

    <%@ include file="/WEB-INF/views/angular-init.jspf" %>

    <div ng-show="successMessage" class="alert alert-success">
        <button class="close" ng-click="successMessage = undefined" type="button">&times;</button>
        {{ successMessage }}
    </div>

    <div ng-show="showErrors" class="alert alert-error">
        <button class="close" ng-click="showErrors = false" type="button">&times;</button>
        <c:forEach items="${ errors }" var="error">
            <c:out value="${ error }"/><br/>
        </c:forEach>
    </div>
	
	<spring:url value="" var="emptyUrl"/>
	<form:form modelAttribute="defaultConfiguration" name="formEditUser" action="${ fn:escapeXml(emptyUrl) }">
        <security:authorize ifAnyGranted="ROLE_ENTERPRISE">
        <div class="panel panel-default">
            <div id="defaultPermissionsPanel" class="panel-heading pointer" style="width:200px"
                 ng-click="editDefaultPermissions = !editDefaultPermissions">
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

        <div class="panel panel-default" ng-controller="CheckLDAPController">
            <div id="ldapSettingsPanel" class="panel-heading pointer" style="width:150px"
                 ng-click="editLdapSettings = !editLdapSettings">
                <h3 class="panel-title">
                    <span ng-hide="editLdapSettings" class="icon icon-chevron-right"></span>
                    <span ng-show="editLdapSettings" class="icon icon-chevron-down"></span>
                    LDAP Settings
                </h3>
            </div>
            <div ng-show="LDAPSuccessMessage" class="alert alert-success">
                <button class="close" ng-click="LDAPSuccessMessage = undefined" type="button">&times;</button>
                {{ LDAPSuccessMessage }}
            </div>
            <div ng-show="error" class="alert alert-danger">
                <button class="close" ng-click="error = undefined" type="button">&times;</button>
                {{ error }}
            </div>
            <div ng-form="form" class="panel-body" ng-show="editLdapSettings">
                <table>
                    <tr>
                        <td style="width:150px" class="no-color">Search Base</td>
                        <td class="no-color">
                            <form:input placeholder="cn=threadfix-ldap,cn=internal,dc=net"
                                        id="activeDirectoryBase"
                                        path="activeDirectoryBase"
                                        cssClass="focus wide"
                                        size="60"
                                        maxlength="255"
                                        ng-model="object.activeDirectoryBase"/>
                        </td>
                        <td class="no-color" style="padding-left: 5px">
                            <form:errors path="activeDirectoryBase" cssClass="errors" />
                        </td>
                        <td class="no-color" style="padding-left: 5px">
                            <a class="btn" style="margin-bottom: 10px; " popover="If you only need to search a particular organizational unit (OU) simply preface the search base with the OU. For example, if you the only unit that requires access to ThreadFix is named 'tfusers', then preface the search base with OU=tfusers.">?</a>
                        </td>
                    </tr>
                    <tr>
                        <td class="no-color">sAMAccountName</td>
                        <td class="no-color">
                            <form:input placeholder="ldap_lookup_account@organization.com"
                                        id="activeDirectoryUsername"
                                        path="activeDirectoryUsername"
                                        cssClass="wide"
                                        size="60"
                                        maxlength="255"
                                        ng-model="object.activeDirectoryUsername"/>
                        </td>
                        <td class="no-color" style="padding-left: 5px">
                            <form:errors path="activeDirectoryUsername" cssClass="errors" />
                        </td>
                    </tr>
                    <tr>
                        <td class="no-color">Password</td>
                        <td class="no-color">
                            <form:input class="wide"
                                        placeholder="ldap_lookup_account password"
                                        id="activeDirectoryCredentials"
                                        type="password"
                                        path="activeDirectoryCredentials"
                                        cssClass="wide"
                                        size="60"
                                        maxlength="255"
                                        ng-model="object.activeDirectoryCredentials"/>
                        </td>
                        <td class="no-color" style="padding-left: 5px">
                            <form:errors path="activeDirectoryCredentials" cssClass="errors" />
                        </td>
                    </tr>
                    <tr>
                        <td class="no-color">URL</td>
                        <td class="no-color">
                            <form:input class="wide"
                                        placeholder="ldap://my-ldap-server:389/"
                                        id="activeDirectoryURL"
                                        path="activeDirectoryURL"
                                        cssClass="wide"
                                        size="60"
                                        maxlength="255"
                                        ng-model="object.activeDirectoryURL"/>
                        </td>
                        <td class="no-color" style="padding-left: 5px">
                            <form:errors path="activeDirectoryURL" cssClass="errors" />
                        </td>
                    </tr>
                </table>
                <a class="btn"
                   id="checkLDAPSettings"
                   ng-class="{ disabled : shouldDisable() }"
                   ng-click="ok(form.$valid)">
                    Check Connection
                </a>
            </div>
        </div>
        <div class="panel panel-default">
            <div id="proxySettingsPanel" class="panel-heading pointer" style="width:150px"
                 ng-click="configureProxySettings = !configureProxySettings">
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
                            <form:input id="proxyPort"
                                        path="proxyPort"
                                        type="number"
                                        cssClass="focus"
                                        size="60"
                                        maxlength="255"
                                        value="${ defaultConfiguration.proxyPort }"/>
                        </td>
                        <td class="no-color" style="padding-left: 5px">
                            <form:errors path="proxyPort" id="proxyPortErrors" cssClass="errors" />
                        </td>
                    </tr>
                    <tr>
                        <td>Use Proxy Credentials</td>
                        <td ng-init="shouldUseProxyCredentials = <c:out value="${ defaultConfiguration.shouldUseProxyCredentials }"/>">
                            <form:checkbox path="shouldUseProxyCredentials" ng-model="shouldUseProxyCredentials"
                                           value="${ defaultConfiguration.shouldUseProxyCredentials }"/>
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
                                            type="password"
                                            path="proxyPassword"
                                            cssClass="focus"
                                            size="60"
                                            maxlength="255"
                                            value="${ defaultConfiguration.proxyPassword }"/>
                            </c:if>
                            <c:if test="${ not empty defaultConfiguration.proxyPasswordEncrypted }">
                                <form:input ng-disabled="!shouldUseProxyCredentials"
                                            id="proxyPassword"
                                            type="password"
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
                        <td>Trustwave Hailstorm</td>
                        <td><form:checkbox path="shouldProxyTrustwaveHailstorm" value="${ defaultConfiguration.shouldProxyTrustwaveHailstorm }"/></td>
                    </tr>
                    <tr>
                        <td>Contrast</td>
                        <td><form:checkbox path="shouldProxyContrast" value="${ defaultConfiguration.shouldProxyContrast }"/></td>
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
                </table>
            </div>
        </div>

        <div class="panel panel-default">
            <div id="defaultSessionTimeoutPermissionsPanel" class="panel-heading pointer" style="width:200px"
                 ng-click="editSessionTimeoutPermissions = !editSessionTimeoutPermissions">
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
                            <form:input id="sessionTimeout" type="number" max="30" min="1" path="sessionTimeout"
                                        placeholder="(in minutes)" cssClass="focus" size="60" maxlength="255"
                                        value="${ defaultConfiguration.sessionTimeout }"/>
                        </td>
                        <td class="no-color" style="padding-left: 5px">
                            <form:errors path="sessionTimeout" cssClass="errors" />
                        </td>
                    </tr>
                </table>
            </div>
        </div>

        <div class="panel panel-default">
            <div id="licenseInformationPanel" class="panel-heading pointer" style="width:200px"
                 ng-click="editLicenseInformationPanel = !editLicenseInformationPanel">
                <h3 class="panel-title">
                    <span ng-hide="editLicenseInformationPanel" class="icon icon-chevron-right"></span>
                    <span ng-show="editLicenseInformationPanel" class="icon icon-chevron-down"></span>
                    License Information
                </h3>
            </div>
            <div class="panel-body" ng-show="editLicenseInformationPanel">
                <c:out value="${ applicationCount }"/> applications used out of <c:out value="${ licenseCount }"/> available for the license. License expires on
                <fmt:formatDate value="${ licenseExpirationDate }" pattern="MM-dd-yyyy" />
            </div>
        </div>
        </security:authorize>

        <div class="panel panel-default">
            <div id="defaultFileUploadLocationSettingsPanel" class="panel-heading pointer" style="width:250px"
                 ng-click="editFileUploadLocationSettings = !editFileUploadLocationSettings">
                <h3 class="panel-title">
                    <span ng-hide="editFileUploadLocationSettings" class="icon icon-chevron-right"></span>
                    <span ng-show="editFileUploadLocationSettings" class="icon icon-chevron-down"></span>
                    File Upload Location Settings
                </h3>
            </div>
            <div class="panel-body" ng-show="editFileUploadLocationSettings">
                <table class="even-sized-rows">
                    <tr>
                        <td style="width:150px" class="no-color">File Upload Location</td>
                        <td class="no-color">
                            <form:input id="fileUploadLocation" path="fileUploadLocation" cssClass="focus" size="60"
                                        maxlength="1024" value="${ defaultConfiguration.fileUploadLocation }"/>
                        </td>
                        <td class="no-color" style="padding-left: 5px" >
                            <form:errors id="fileUploadLocationErrors" path="fileUploadLocation" cssClass="errors"/>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

		<div class="panel panel-default">
            <div id="defaultDashboardSettingsPanel" class="panel-heading pointer" style="width:200px" ng-click="editDashboardSettings = !editDashboardSettings">
                <h3 class="panel-title">
                    <span ng-hide="editDashboardSettings" class="icon icon-chevron-right"></span>
                    <span ng-show="editDashboardSettings" class="icon icon-chevron-down"></span>
                    Dashboard Settings
                </h3>
            </div>
            <div class="panel-body" ng-show="editDashboardSettings">
                <table>
                    <tr>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Top Left Report</b>
                            </div>
                            <div>
                                <form:select id="dashboardTopLeftSelect" path="dashboardTopLeft.id">
                                    <form:options items="${ dashboardReports }" itemValue="id" itemLabel="displayName" />
                                </form:select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Top Right Report</b>
                            </div>
                            <div>
                                <form:select id="dashboardTopRightSelect" path="dashboardTopRight.id">
                                    <form:options items="${ dashboardReports }" itemValue="id" itemLabel="displayName" />
                                </form:select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Bottom Left Report</b>
                            </div>
                            <div>
                                <form:select id="dashboardBottomLeftSelect" path="dashboardBottomLeft.id">
                                    <form:options items="${ dashboardReports }" itemValue="id" itemLabel="displayName" />
                                </form:select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Bottom Right Report</b>
                            </div>
                            <div>
                                <form:select id="dashboardBottomRightSelect" path="dashboardBottomRight.id">
                                    <form:options items="${ dashboardReports }" itemValue="id" itemLabel="displayName" />
                                </form:select>
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
        </div>

		<div class="panel panel-default">
            <div id="defaultApplicationDetailPageSettingsPanel" class="panel-heading pointer" style="width:300px"
                 ng-click="editApplicationDetailPageSettings = !editApplicationDetailPageSettings">
                <h3 class="panel-title">
                    <span ng-hide="editApplicationDetailPageSettings" class="icon icon-chevron-right"></span>
                    <span ng-show="editApplicationDetailPageSettings" class="icon icon-chevron-down"></span>
                    Application Detail Page Settings
                </h3>
            </div>
            <div class="panel-body" ng-show="editApplicationDetailPageSettings">
                <table>
                    <tr>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Top Left Report</b>
                            </div>
                            <div>
                                <form:select id="applicationTopLeftSelect" path="applicationTopLeft.id">
                                    <form:options items="${ applicationReports }" itemValue="id" itemLabel="displayName" />
                                </form:select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Top Right Report</b>
                            </div>
                            <div>
                                <form:select id="applicationTopRightSelect" path="applicationTopRight.id">
                                    <form:options items="${ applicationReports }" itemValue="id" itemLabel="displayName" />
                                </form:select>
                            </div>
                        </td>
                </table>
            </div>
        </div>

		<div class="panel panel-default">
            <div id="defaultTeamDetailPageSettingsPanel" class="panel-heading pointer" style="width:250px"
                 ng-click="editTeamDetailPageSettings = !editTeamDetailPageSettings">
                <h3 class="panel-title">
                    <span ng-hide="editTeamDetailPageSettings" class="icon icon-chevron-right"></span>
                    <span ng-show="editTeamDetailPageSettings" class="icon icon-chevron-down"></span>
                    Team Detail Page Settings
                </h3>
            </div>
            <div class="panel-body" ng-show="editTeamDetailPageSettings">
                <table>
                    <tr>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Top Left Report</b>
                            </div>
                            <div>
                                <form:select id="teamTopLeftSelect" path="teamTopLeft.id">
                                    <form:options items="${ teamReports }" itemValue="id" itemLabel="displayName" />
                                </form:select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Top Right Report</b>
                            </div>
                            <div>
                                <form:select id="teamTopRightSelect" path="teamTopRight.id">
                                    <form:options items="${ teamReports }" itemValue="id" itemLabel="displayName" />
                                </form:select>
                            </div>
                        </td>
                </table>
            </div>
        </div>

		<br/>
		<button ng-disabled="form.$invalid" class="btn btn-primary" type="submit" id="updateDefaultsButton">Save Changes</button>
	</form:form>
</body>
