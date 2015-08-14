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

    <tabset>
        <security:authorize ifAnyGranted="ROLE_ENTERPRISE">
            <tab id="loginTab" heading="Login Settings" ng-click="setTab('login')" active="tab.login">
                <div ng-form="configForm" name="form">
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
                                            <input type="checkbox" id="globalGroupEnabledCheckbox" name="globalGroupEnabled" ng-model="object.globalGroupEnabled"/>
                                        </td>
                                        <td class="inputValue">
                                            <select id="roleSelect" ng-model="object.defaultRoleId" name="defaultRoleId" ng-disabled="!object.globalGroupEnabled" required>
                                                <option ng-repeat="role in roleList" ng-selected="selectedRole(role.id)" value="{{ role.id }}">{{ role.displayName }}</option>
                                            </select>
                                        </td>
                                        <td style="border: 0 solid black; background-color: white; padding-left: 5px">
                                            <a class="btn" popover="When LDAP users log in, ThreadFix can assign them a default role. If no role is selected here, the user will be unable to access any data in ThreadFix. To configure per-team and per-application permissions for an LDAP user, create a ThreadFix user with the same username.">?</a>
                                            <span id="globalGroupEnabledServerError" class="errors" ng-show="object.globalGroupEnabled_error"> {{ object.globalGroupEnabled_error }} </span>
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
                                               ng-model="object.activeDirectoryBase"/>
                                    </td>
                                    <td class="no-color" style="padding-left: 5px">
                                        <span id="activeDirectoryBaseCharacterLimitError" class="errors" ng-show="form.activeDirectoryBase.$dirty && form.activeDirectoryBase.$error.maxlength">Over 255 characters limit!</span>
                                        <span id="activeDirectoryBaseServerError" class="errors" ng-show="object.activeDirectoryBase_error"> {{ object.activeDirectoryUsername_error }}</span>
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
                                               ng-model="object.activeDirectoryUsername"/>
                                    </td>
                                    <td class="no-color" style="padding-left: 5px">
                                        <span id="activeDirectoryUsernameCharacterLimitError" class="errors" ng-show="form.activeDirectoryUsername.$dirty && form.activeDirectoryUsername.$error.maxlength">Over 255 characters limit!</span>
                                        <span id="activeDirectoryUsernameServerError" class="errors" ng-show="object.activeDirectoryUsername_error"> {{ object.activeDirectoryUsername_error }}</span>
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
                                               ng-model="object.activeDirectoryCredentials"/>
                                    </td>
                                    <td class="no-color" style="padding-left: 5px">
                                        <span id="activeDirectoryCredentialsCharacterLimitError" class="errors" ng-show="form.activeDirectoryCredentials.$dirty && form.activeDirectoryCredentials.$error.maxlength">Over 255 characters limit!</span>
                                        <span id="activeDirectoryCredentialsServerError" class="errors" ng-show="object.activeDirectoryCredentials_error"> {{ object.activeDirectoryCredentials_error }}</span>
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
                                               ng-model="object.activeDirectoryURL"/>
                                    </td>
                                    <td class="no-color" style="padding-left: 5px">
                                        <span id="activeDirectoryURLCharacterLimitError" class="errors" ng-show="form.activeDirectoryURL.$dirty && form.activeDirectoryURL.$error.maxlength">Over 255 characters limit!</span>
                                        <span id="activeDirectoryURLServerError" class="errors" ng-show="object.activeDirectoryURL_error"> {{ object.activeDirectoryURL }}</span>
                                    </td>
                                </tr>
                            </table>

                            <button id="checkLDAPSettings" ng-disabled="shouldDisable()" class="btn" ng-click="ok(form.$valid)">
                                Check Connection
                            </button>
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
                                               ng-model="object.sessionTimeout"/>
                                    </td>
                                    <td class="no-color" style="padding-left: 5px">
                                        <span id="sessionTimeoutNumberLimitError" class="errors" ng-show="form.sessionTimeout.$dirty && form.sessionTimeout.$error.max">Max value is 30 seconds.</span>
                                        <span id="sessionTimeoutValidNumberError" class="errors" ng-show="form.sessionTimeout.$dirty && form.sessionTimeout.$error.number">Not valid number!</span>
                                        <span id="sessionTimeoutServerError" class="errors" ng-show="object.sessionTimeout_error"> {{ object.sessionTimeout_error }}</span>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>

                    <button id="submit"
                            ng-class="{ disabled : form.$invalid }"
                            class="btn btn-primary"
                            ng-mouseenter="form.$dirty = true"
                            ng-hide="loading"
                            ng-click="submit(form.$valid)">Save Changes</button>
                </div>
            </tab>
        </security:authorize>

        <tab id="reportTab" heading="Report Settings" ng-click="setTab('report')" active="tab.report">
            <div ng-form="configForm" name="form">
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
                            <tr ng-show="object.dashboardReport_error">
                                <td style="padding: 0 0 5px 5px" colspan="4">
                                    <span id="dashboardReportServerError" class="errors" ng-show="object.dashboardReport_error">{{ object.dashboardReport_error }}</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding-left: 5px">
                                    <div>
                                        <b>Top Left Report</b>
                                    </div>
                                    <div>
                                        <select ng-options="dashboardReport.displayName for dashboardReport in dashboardReports track by dashboardReport.id"
                                                id="dashboardTopLeftSelect" name="dashboardTopLeft" ng-model="object.dashboardTopLeft" ></select>
                                    </div>
                                </td>
                                <td style="padding-left: 5px">
                                    <div>
                                        <b>Top Right Report</b>
                                    </div>
                                    <div>
                                        <select ng-options="dashboardReport.displayName for dashboardReport in dashboardReports track by dashboardReport.id"
                                                id="dashboardTopRightSelect" name="dashboardTopRight" ng-model="object.dashboardTopRight" ></select>
                                    </div>
                                </td>
                                <td style="padding-left: 5px">
                                    <div>
                                        <b>Bottom Left Report</b>
                                    </div>
                                    <div>
                                        <select ng-options="dashboardReport.displayName for dashboardReport in dashboardReports track by dashboardReport.id"
                                                id="dashboardBottomLeftSelect" name="dashboardBottomLeft" ng-model="object.dashboardBottomLeft" ></select>
                                    </div>
                                </td>
                                <td style="padding-left: 5px">
                                    <div>
                                        <b>Bottom Right Report</b>
                                    </div>
                                    <div>
                                        <select ng-options="dashboardReport.displayName for dashboardReport in dashboardReports track by dashboardReport.id"
                                                id="dashboardBottomRightSelect" name="dashboardBottomRight" ng-model="object.dashboardBottomRight" ></select>
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
                            <tr ng-show="object.applicationReport_error">
                                <td style="padding: 0 0 5px 5px" colspan="4">
                                    <span id="applicationReportServerError" class="errors" ng-show="object.applicationReport_error">{{ object.applicationReport_error }}</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding-left: 5px">
                                    <div>
                                        <b>Top Left Report</b>
                                    </div>
                                    <div>
                                        <select ng-options="applicationReport.displayName for applicationReport in applicationReports track by applicationReport.id"
                                                id="applicationTopLeftSelect" name="applicationTopLeft" ng-model="object.applicationTopLeft" ></select>
                                    </div>
                                </td>
                                <td style="padding-left: 5px">
                                    <div>
                                        <b>Top Right Report</b>
                                    </div>
                                    <div>
                                        <select ng-options="applicationReport.displayName for applicationReport in applicationReports track by applicationReport.id"
                                                id="applicationTopRightSelect" name="applicationTopRight" ng-model="object.applicationTopRight" ></select>
                                    </div>
                                </td>
                            </tr>
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
                            <tr ng-show="object.teamReport_error">
                                <td style="padding: 0 0 5px 5px" colspan="4">
                                    <div id="teamReportServerError" class="errors" ng-show="object.teamReport_error">{{ object.teamReport_error }}</div>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding-left: 5px">
                                    <div>
                                        <b>Top Left Report</b>
                                    </div>
                                    <div>
                                        <select ng-options="teamReport.displayName for teamReport in teamReports track by teamReport.id"
                                                id="teamTopLeftSelect" name="teamTopLeft" ng-model="object.teamTopLeft" ></select>
                                    </div>
                                </td>
                                <td style="padding-left: 5px">
                                    <div>
                                        <b>Top Right Report</b>
                                    </div>
                                    <div>
                                        <select ng-options="teamReport.displayName for teamReport in teamReports track by teamReport.id"
                                                id="teamTopRightSelect" name="teamTopRight" ng-model="object.teamTopRight"></select>
                                    </div>
                                </td>
                            </tr>
                        </table>
                    </div>
                </div>

                <button id="submit"
                        ng-class="{ disabled : form.$invalid }"
                        class="btn btn-primary"
                        ng-mouseenter="form.$dirty = true"
                        ng-hide="loading"
                        ng-click="submit(form.$valid)">Save Changes</button>
            </div>
        </tab>

        <tab id="otherTab" heading="Other Settings" ng-click="setTab('other')" active="tab.other">
            <div ng-form="configForm" name="form">

                <security:authorize ifAnyGranted="ROLE_ENTERPRISE">

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
                                               ng-model="object.proxyHost"/>
                                    </td>
                                    <td class="no-color" style="padding-left: 5px">
                                        <span id="proxyHostCharacterLimitError" class="errors" ng-show="form.proxyHost.$dirty && form.proxyHost.$error.maxlength">Over 255 characters limit!</span>
                                        <span id="proxyHostServerError" class="errors" ng-show="object.proxyHost_error"> {{ object.proxyHost_error }}</span>
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
                                               ng-model="object.proxyPort"/>
                                    </td>
                                    <td class="no-color" style="padding-left: 5px">
                                        <span id="proxyPortServerError" class="errors" ng-show="object.proxyPort_error"> {{ object.proxyPort_error }}</span>
                                        <span id="proxyPortCharacterLimitError" class="errors" ng-show="form.proxyPort.$dirty && form.proxyPort.$error.maxlength">Over 255 characters limit!</span>
                                    </td>
                                </tr>
                                <tr>
                                    <td>Use Proxy Credentials</td>
                                    <td>
                                        <input type="checkbox" name="shouldUseProxyCredentials" ng-model="object.shouldUseProxyCredentials"/>
                                    </td>
                                </tr>
                                <tr>
                                    <td class="no-color">Proxy Username</td>
                                    <td class="no-color">
                                        <input ng-show="!object.proxyUsernameEncrypted"
                                               ng-disabled="!object.shouldUseProxyCredentials"
                                               id="proxyUsername"
                                               name="proxyUsername"
                                               class="focus"
                                               size="60"
                                               type="text"
                                               maxlength="255"
                                               ng-model="object.proxyUsername"/>
                                        <input ng-show="object.proxyUsernameEncrypted"
                                               ng-disabled="!object.shouldUseProxyCredentials"
                                               id="proxyUsername"
                                               name="proxyUsername"
                                               class="focus"
                                               size="60"
                                               type="text"
                                               maxlength="255"
                                               ng-model="object.proxyUsername"
                                               placeholder="Use object username"/>
                                    </td>
                                    <td class="no-color" style="padding-left: 5px">
                                        <span id="proxyUsernameCharacterLimitError" class="errors" ng-show="form.proxyUsername.$dirty && form.proxyUsername.$error.maxlength">Over 255 characters limit!</span>
                                        <span id="proxyUsernameServerError" class="errors" ng-show="object.proxyUsername_error"> {{ object.proxyUsername_error }}</span>
                                    </td>
                                </tr>
                                <tr>
                                    <td class="no-color">Proxy Password</td>
                                    <td class="no-color">
                                        <input ng-show="!object.proxyPasswordEncrypted"
                                               ng-disabled="!object.shouldUseProxyCredentials"
                                               id="proxyPassword"
                                               type="password"
                                               name="proxyPassword"
                                               class="focus"
                                               size="60"
                                               maxlength="255"
                                               ng-model="object.proxyPassword"/>
                                        <input ng-show="object.proxyPasswordEncrypted"
                                               ng-disabled="!object.shouldUseProxyCredentials"
                                               id="proxyPassword"
                                               type="password"
                                               name="proxyPassword"
                                               cssClass="focus"
                                               size="60"
                                               maxlength="255"
                                               ng-model="object.proxyPassword"
                                               placeholder="Use configured password"/>
                                    </td>
                                    <td class="no-color" style="padding-left: 5px">
                                        <span id="proxyPasswordCharacterLimitError" class="errors" ng-show="form.proxyPassword.$dirty && form.proxyPassword.$error.maxlength">Over 255 characters limit!</span>
                                        <span id="proxyPasswordServerError" class="errors" ng-show="object.proxyPassword_error"> {{ object.proxyPassword_error }}</span>
                                    </td>
                                </tr>
                                <tr>
                                    <td>Qualys</td>
                                    <td><input type="checkbox" name="shouldProxyQualys" ng-model="object.shouldProxyQualys"/></td>
                                </tr>
                                <tr>
                                    <td>Veracode</td>
                                    <td><input type="checkbox" name="shouldProxyVeracode" ng-model="object.shouldProxyVeracode"/></td>
                                </tr>
                                <tr>
                                    <td>WhiteHat Sentinel</td>
                                    <td><input type="checkbox" name="shouldProxyWhiteHat" ng-model="object.shouldProxyWhiteHat"/></td>
                                </tr>
                                <tr>
                                    <td>Trustwave Hailstorm</td>
                                    <td><input type="checkbox" name="shouldProxyTrustwaveHailstorm" ng-model="object.shouldProxyTrustwaveHailstorm"/></td>
                                </tr>
                                <tr>
                                    <td>Contrast</td>
                                    <td><input type="checkbox" name="shouldProxyContrast" ng-model="object.shouldProxyContrast"/></td>
                                </tr>
                                <tr>
                                    <td>TFS</td>
                                    <td><input type="checkbox" name="shouldProxyTFS" ng-model="object.shouldProxyTFS"/></td>
                                </tr>
                                <tr>
                                    <td>Bugzilla</td>
                                    <td><input type="checkbox" name="shouldProxyBugzilla" ng-model="object.shouldProxyBugzilla"/></td>
                                </tr>
                                <tr>
                                    <td>Jira</td>
                                    <td><input type="checkbox" name="shouldProxyJira" ng-model="object.shouldProxyJira"/></td>
                                </tr>
                                <tr>
                                    <td>Version One</td>
                                    <td><input type="checkbox" name="shouldProxyVersionOne" ng-model="object.shouldProxyVersionOne"/></td>
                                </tr>
                                <tr>
                                    <td>HP Quality Center</td>
                                    <td><input type="checkbox" name="shouldProxyHPQC" ng-model="object.shouldProxyHPQC"/></td>
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
                                           maxlength="1024" ng-model="object.fileUploadLocation"/>
                                </td>
                                <td class="no-color" style="padding-left: 5px">
                                    <span id="fileUploadLocationCharacterLimitError" class="errors" ng-show="form.fileUploadLocation.$dirty && form.fileUploadLocation.$error.maxlength">Over 1024 characters limit!</span>
                                    <span id="fileUploadLocationServerError" class="errors" ng-show="object.fileUploadLocation_error"> {{ object.fileUploadLocation_error }}</span>
                                </td>
                            </tr>
                        </table>
                    </div>
                </div>

                <button id="submit"
                        ng-class="{ disabled : form.$invalid }"
                        class="btn btn-primary"
                        ng-mouseenter="form.$dirty = true"
                        ng-hide="loading"
                        ng-click="submit(form.$valid)">Save Changes</button>
            </div>
        </tab>
    </tabset>
</body>
