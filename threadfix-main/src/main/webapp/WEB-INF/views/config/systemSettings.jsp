<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>System Settings</title>
    <cbs:cachebustscript src="/scripts/system-settings-controller.js"/>
</head>

<body id="config" ng-controller="SystemSettingsController">
    <h2>System Settings</h2>

    <%@ include file="/WEB-INF/views/angular-init.jspf" %>
    <%@ include file="/WEB-INF/views/successMessage.jspf"%>
    <%@ include file="/WEB-INF/views/errorMessage.jspf"%>

    <%--<div ng-show="showErrors" class="alert alert-error">--%>
        <%--<button class="close" ng-click="showErrors = false" type="button">&times;</button>--%>
        <%--<c:forEach items="${ errors }}" var="error">--%>
            <%--<c:out value="${ error }}"/><br/>--%>
        <%--</c:forEach>--%>
    <%--</div>--%>
	
	<div ng-form="form" name="formEditUser">
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
                                <td class="inputValue" style="text-align: left;">
                                    <input type="checkbox" id="globalGroupEnabledCheckbox" name="globalGroupEnabled" ng-model="config.globalGroupEnabled"/>
                                </td>
                                <td class="inputValue">
                                    <select id="roleSelect" ng-model="config.defaultRoleId" name="defaultRoleId" ng-disabled="!config.globalGroupEnabled">
                                        <option ng-repeat="role in roleList" value="{{ role.id }}">{{ role.displayName }}</option>
                                    </select>
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

            <div class="panel panel-default">
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
                <div ng-show="LDAPError" class="alert alert-danger">
                    <button class="close" ng-click="LDAPError = undefined" type="button">&times;</button>
                    {{ LDAPError }}
                </div>
                <div ng-form="form" class="panel-body" ng-show="editLdapSettings">
                    <table>
                        <tr>
                            <td style="width:150px" class="no-color">Search Base</td>
                            <td class="no-color">
                                <input placeholder="cn=threadfix-ldap,cn=internal,dc=net"
                                       type="text"
                                       id="activeDirectoryBase"
                                       name="activeDirectoryBase"
                                       class="focus wide"
                                       size="60"
                                       maxlength="255"
                                       ng-model="config.activeDirectoryBase"/>
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
                                <input placeholder="ldap_lookup_account@organization.com"
                                       type="text"
                                       id="activeDirectoryUsername"
                                       name="activeDirectoryUsername"
                                       class="wide"
                                       size="60"
                                       maxlength="255"
                                       ng-model="config.activeDirectoryUsername"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="activeDirectoryUsername" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">Password</td>
                            <td class="no-color">
                                <input class="wide"
                                       placeholder="ldap_lookup_account password"
                                       id="activeDirectoryCredentials"
                                       type="password"
                                       name="activeDirectoryCredentials"
                                       size="60"
                                       maxlength="255"
                                       ng-model="config.activeDirectoryCredentials"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="activeDirectoryCredentials" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">URL</td>
                            <td class="no-color">
                                <input placeholder="ldap://my-ldap-server:389/"
                                       type="text"
                                       id="activeDirectoryURL"
                                       name="activeDirectoryURL"
                                       class="wide"
                                       size="60"
                                       maxlength="255"
                                       ng-model="config.activeDirectoryURL"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="activeDirectoryURL" cssClass="errors" />
                            </td>
                        </tr>
                    </table>
                    <a class="btn" id="checkLDAPSettings" ng-class="{ disabled : shouldDisable() }}" ng-click="ok(form.$valid)">
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
                                <input id="proxyHost"
                                       name="proxyHost"
                                       type="text"
                                       class="focus"
                                       size="60"
                                       maxlength="255"
                                       ng-model="config.proxyHost"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="activeDirectoryUsername" id="proxyHostErrors" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">Proxy Port</td>
                            <td class="no-color">
                                <input id="proxyPort"
                                       name="proxyPort"
                                       type="number"
                                       class="focus"
                                       size="60"
                                       maxlength="255"
                                       ng-model="config.proxyPort"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="proxyPort" id="proxyPortErrors" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td>Use Proxy Credentials</td>
                            <td>
                                <input type="checkbox" name="shouldUseProxyCredentials" ng-model="config.shouldUseProxyCredentials"/>
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">Proxy Username</td>
                            <td class="no-color">
                                <input ng-show="!config.proxyUsernameEncrypted"
                                       ng-disabled="!config.shouldUseProxyCredentials"
                                       id="proxyUsername"
                                       name="proxyUsername"
                                       class="focus"
                                       size="60"
                                       type="text"
                                       maxlength="255"
                                       ng-model="config.proxyUsername"/>
                                <input ng-show="config.proxyUsernameEncrypted"
                                       ng-disabled="!config.shouldUseProxyCredentials"
                                       id="proxyUsername"
                                       name="proxyUsername"
                                       class="focus"
                                       size="60"
                                       type="text"
                                       maxlength="255"
                                       ng-model="config.proxyUsername"
                                       placeholder="Use configured username"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="proxyUsername" id="proxyUsernameErrors" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td class="no-color">Proxy Password</td>
                            <td class="no-color">
                                <input ng-show="!config.proxyPasswordEncrypted"
                                       ng-disabled="!config.shouldUseProxyCredentials"
                                       id="proxyPassword"
                                       type="password"
                                       name="proxyPassword"
                                       class="focus"
                                       size="60"
                                       maxlength="255"
                                       ng-model="config.proxyPassword"/>
                                <input ng-show="config.proxyPasswordEncrypted"
                                       ng-disabled="!config.shouldUseProxyCredentials"
                                       id="proxyPassword"
                                       type="password"
                                       name="proxyPassword"
                                       cssClass="focus"
                                       size="60"
                                       maxlength="255"
                                       ng-model="config.proxyPassword"
                                       placeholder="Use configured password"/>
                            </td>
                            <td class="no-color" style="padding-left: 5px">
                                <form:errors path="proxyPassword" id="proxyPasswordErrors" cssClass="errors" />
                            </td>
                        </tr>
                        <tr>
                            <td>Qualys</td>
                            <td><input type="checkbox" name="shouldProxyQualys" ng-model="config.shouldProxyQualys"/></td>
                        </tr>
                        <tr>
                            <td>Veracode</td>
                            <td><input type="checkbox" name="shouldProxyVeracode" ng-model="config.shouldProxyVeracode"/></td>
                        </tr>
                        <tr>
                            <td>WhiteHat Sentinel</td>
                            <td><input type="checkbox" name="shouldProxyWhiteHat" ng-model="config.shouldProxyWhiteHat"/></td>
                        </tr>
                        <tr>
                            <td>Trustwave Hailstorm</td>
                            <td><input type="checkbox" name="shouldProxyTrustwaveHailstorm" ng-model="config.shouldProxyTrustwaveHailstorm"/></td>
                        </tr>
                        <tr>
                            <td>Contrast</td>
                            <td><input type="checkbox" name="shouldProxyContrast" ng-model="config.shouldProxyContrast"/></td>
                        </tr>
                        <tr>
                            <td>TFS</td>
                            <td><input type="checkbox" name="shouldProxyTFS" ng-model="config.shouldProxyTFS"/></td>
                        </tr>
                        <tr>
                            <td>Bugzilla</td>
                            <td><input type="checkbox" name="shouldProxyBugzilla" ng-model="config.shouldProxyBugzilla"/></td>
                        </tr>
                        <tr>
                            <td>Jira</td>
                            <td><input type="checkbox" name="shouldProxyJira" ng-model="config.shouldProxyJira"/></td>
                        </tr>
                        <tr>
                            <td>Version One</td>
                            <td><input type="checkbox" name="shouldProxyVersionOne" ng-model="config.shouldProxyVersionOne"/></td>
                        </tr>
                        <tr>
                            <td>HP Quality Center</td>
                            <td><input type="checkbox" name="shouldProxyHPQC" ng-model="config.shouldProxyHPQC"/></td>
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
                                <input id="sessionTimeout"
                                       type="number"
                                       max="30"
                                       min="1"
                                       name="sessionTimeout"
                                       placeholder="(in minutes)"
                                       class="focus"
                                       size="60"
                                       maxlength="255"
                                       ng-model="config.sessionTimeout"/>
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
                    {{ applicationCount }} applications used out of {{ licenseCount }} available for the license. License expires on
                    <span ng-bind="licenseExpirationDate | date:'MM-dd-yyyy'"/>
                </div>
            </div>
        </security:authorize>

        <div class="panel panel-default">
            <div id="defaultFileUploadLocationSettingsPanel" class="panel-heading pointer" style="width:250px"
                 ng-click="editFileUploadLocationSettings = !editFileUploadLocationSettings">
                <h3 class="panel-title">
                    <span ng-hide="editFileUploadLocationSettings" class="icon icon-chevron-right"></span>
                    <span ng-show="editFileUploadLocationSettings" class="icon icon-chevron-down"></span>
                    File Upload Location
                </h3>
            </div>
            <div class="panel-body" ng-show="editFileUploadLocationSettings">
                <table class="even-sized-rows">
                    <tr>
                        <td style="width:150px" class="no-color">File Upload Location</td>
                        <td class="no-color">
                            <input id="fileUploadLocation" type="text" name="fileUploadLocation" class="focus" size="60"
                                        maxlength="1024" ng-model="config.fileUploadLocation"/>
                        </td>
                        <td class="no-color" style="padding-left: 5px">
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
                                <select ng-options="dashboardReport.displayName for dashboardReport in dashboardReports track by dashboardReport.id"
                                        id="dashboardTopLeftSelect" name="dashboardTopLeft" ng-model="config.dashboardTopLeft" ></select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Top Right Report</b>
                            </div>
                            <div>
                                <select ng-options="dashboardReport.displayName for dashboardReport in dashboardReports track by dashboardReport.id"
                                        id="dashboardTopRightSelect" name="dashboardTopRight" ng-model="config.dashboardTopRight" ></select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Bottom Left Report</b>
                            </div>
                            <div>
                                <select ng-options="dashboardReport.displayName for dashboardReport in dashboardReports track by dashboardReport.id"
                                        id="dashboardBottomLeftSelect" name="dashboardBottomLeft" ng-model="config.dashboardBottomLeft" ></select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Bottom Right Report</b>
                            </div>
                            <div>
                                <select ng-options="dashboardReport.displayName for dashboardReport in dashboardReports track by dashboardReport.id"
                                        id="dashboardBottomRightSelect" name="dashboardBottomRight" ng-model="config.dashboardBottomRight" ></select>
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
                                <select ng-options="applicationReport.displayName for applicationReport in applicationReports track by applicationReport.id"
                                        id="applicationTopLeftSelect" name="applicationTopLeft" ng-model="config.applicationTopLeft" ></select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Top Right Report</b>
                            </div>
                            <div>
                                <select ng-options="applicationReport.displayName for applicationReport in applicationReports track by applicationReport.id"
                                        id="applicationTopRightSelect" name="applicationTopRight" ng-model="config.applicationTopRight" ></select>
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
                                <select ng-options="teamReport.displayName for teamReport in teamReports track by teamReport.id"
                                        id="teamTopLeftSelect" name="teamTopLeft" ng-model="config.teamTopLeft" ></select>
                            </div>
                        </td>
                        <td style="padding-left: 5px">
                            <div>
                                <b>Top Right Report</b>
                            </div>
                            <div>
                                <select ng-options="teamReport.displayName for teamReport in teamReports track by teamReport.id"
                                        id="teamTopRightSelect" name="teamTopRight" ng-model="config.teamTopRight"></select>
                            </div>
                        </td>
                </table>
            </div>
        </div>

        <a class="btn btn-primary" id="updateDefaultsButton" ng-disabled="configForm.$invalid" ng-click="submit(configForm.$valid)">
            Save Changes
        </a>
	</div>
</body>
