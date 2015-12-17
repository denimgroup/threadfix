<%@ include file="/common/taglibs.jsp"%>

<div id="logoBar"></div>
<div id="logo">
	<a  href="<spring:url value="/dashboard" htmlEscape="true"/>">
		<img src="<%=request.getContextPath()%>/images/TF_logo_w_arrow_strap.png" class="transparent_png" alt="Threadfix" />
	</a>
</div>

<div id="menu">
	<table>
		<tbody>
			<tr>
				<security:authorize ifNotGranted="ROLE_CAN_GENERATE_REPORTS">
					<td id="tab-spaces" style="width:110px;background:none;"></td>
				</security:authorize>

                <spring:url value="/dashboard" htmlEscape="true" var="dashboardLink"/>
				<td class="pointer" id="tab-dashboard" style="width: 130px;">
					<a id="dashboardHeader" href="<spring:url value="/dashboard" htmlEscape="true"/>">Dashboard</a>
				</td>
				<td class="pointer" id="tab-apps" style="width: 120px;">
					<a id="orgHeader" href="<spring:url value="/teams" htmlEscape="true"/>">Teams</a>
				</td>
				<td class="pointer" id="tab-scans" style="width: 90px;">
					<a id="scansHeader" href="<spring:url value="/scans" htmlEscape="true"/>">Scans</a>
				</td>
				<security:authorize ifAnyGranted="ROLE_CAN_GENERATE_REPORTS">
					<td class="pointer" id="tab-reports" style="width: 110px;">
						<a id="reportsHeader" href="<spring:url value="/reports" htmlEscape="true"/>">Analytics</a>
					</td>
				</security:authorize>
				<td id="tab-user" style="width:130px; white-space:nowrap">
					<div class="dropdown normalLinks">
					<div class="dropdown-toggle" data-target="#" style="height:32px;text-align:center;">
						<div style="display:inline-block;margin-top:6px;">
						<a id="tabUserAnchor" href="#">
							<i class="icon-user icon-white"></i> <security:authentication property="principal.username"/>
							<span id="header-caret" class="caret-down" style="padding-left:0px"></span>
						</a>
						</div>
				  	 </div>
					<ul id="userConfigurationHeader" class="dropdown-menu pull-right config-header" style="text-align:right;">
						
						<security:authentication var="principal" property="principal" />
						<c:if test="${ not principal.isLdapUser }">
							<li class="normalLinks">
						    	<a id="changePasswordLink" href="<spring:url value="/configuration/users/password" 
						    			htmlEscape="true"/>">
						    		Change My Password
						    	</a>
						    </li>
						</c:if>

						<li class="normalLinks">
							<a id="logoutLink" href="<spring:url value="/j_spring_security_logout" htmlEscape="true" />">
								<spring:message code="user.logout"/>
							</a>
						</li>
					</ul>
				   </div>
				</td>
                <security:authorize ifAllGranted="ROLE_ENTERPRISE">
                    <jsp:include page="/app/history/recent"/>
                </security:authorize>
				<td id="tab-config" style="width: 30px;padding-left:0;">
					
					<div class="dropdown normalLinks">
					<div class="dropdown-toggle" data-target="#" style="height:32px;text-align:center;">
						<div style="display:inline-block;margin-top:6px;">
						<a id="tabConfigAnchor" href="#">
							<i class="icon-cog icon-white"></i>
						</a>
						</div>
				  	 </div>
					<ul id="configurationHeader" class="dropdown-menu pull-right config-header" style="text-align:right;">
                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS,ROLE_CAN_MANAGE_GRC_TOOLS,ROLE_CAN_MANAGE_REMOTE_PROVIDERS, ROLE_CAN_MANAGE_SCAN_AGENTS, ROLE_CAN_MANAGE_WAFS">
                            <li class="dropdown-submenu left pull-left normalLinks">
                                <a tabindex="-1" href="#" id="manageIntegrations">Integrations</a>
                                <ul class="dropdown-menu" style="text-align:right; left: -177px;" tabindex="-1">
                                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS">
                                        <li class="normalLinks">
                                            <a id="defectTrackersLink" href="<spring:url value="/configuration/defecttrackers" htmlEscape="true"/>">Defect Trackers</a>
                                        </li>
                                    </security:authorize>
                                    <security:authorize ifAllGranted="ROLE_CAN_MANAGE_GRC_TOOLS,ROLE_ENTERPRISE">
                                        <li class="normalLinks">
                                            <a id="grcToolsLink" href="<spring:url value="/configuration/grctools" htmlEscape="true"/>">GRC Tools</a>
                                        </li>
                                    </security:authorize>

                                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_REMOTE_PROVIDERS">
                                        <li class="normalLinks">
                                            <a id="remoteProvidersLink" href="<spring:url value="/configuration/remoteproviders" htmlEscape="true"/>">Remote Providers</a>
                                        </li>
                                    </security:authorize>
                                    <security:authorize ifAllGranted="ROLE_ENTERPRISE, ROLE_CAN_MANAGE_SCAN_AGENTS">
                                        <li class="normalLinks">
                                            <a id="scanQueueLink" href="<spring:url value="/configuration/scanqueue" htmlEscape="true"/>">Scan Agent Tasks</a>
                                        </li>
                                    </security:authorize>

                                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_WAFS">
                                        <li class="normalLinks">
                                            <a id="wafsLink" href="<spring:url value="/wafs" htmlEscape="true"/>">WAFs</a>
                                        </li>
                                    </security:authorize>
                                 </ul>
                            </li>
                        </security:authorize>
                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_SYSTEM_SETTINGS,ROLE_CAN_MANAGE_CUSTOM_CWE_TEXT, ROLE_CAN_MANAGE_SCAN_RESULT_FILTERS, ROLE_CAN_MANAGE_TAGS,ROLE_CAN_MANAGE_POLICIES, ROLE_CAN_MODIFY_VULNERABILITIES,ROLE_CAN_MANAGE_VULN_FILTERS">
                            <li class="dropdown-submenu left pull-left normalLinks">
                                <a tabindex="-1" href="#" id="manageCustomLink">Customize</a>
                                <ul class="dropdown-menu" style="text-align:right; width: 230px; left: -242px;" tabindex="-1">
                                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_CUSTOM_CWE_TEXT,ROLE_CAN_MANAGE_VULN_FILTERS">
                                        <li class="normalLinks">
                                            <a id="customizeThreadFixVulnerabilityTypesLink" href="<spring:url value="/configuration/filters" htmlEscape="true"/>">ThreadFix Vulnerability Types</a>
                                        </li>
                                    </security:authorize>

                                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_VULN_FILTERS">
                                        <li class="normalLinks">
                                            <a id="customizeScannerVulnerabilityTypesLink" href="<spring:url value="/mappings/index" htmlEscape="true"/>">Scanner Vulnerability Types</a>
                                        </li>
                                    </security:authorize>

                                    <security:authorize ifAnyGranted="ROLE_CAN_MODIFY_VULNERABILITIES">
                                        <li class="normalLinks">
                                            <a id="customizeThreadFixSeveritiesLink" href="<spring:url value="/severities" htmlEscape="true"/>">ThreadFix Severities</a>
                                        </li>
                                    </security:authorize>

                                    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_SYSTEM_SETTINGS,ROLE_CAN_MANAGE_SCAN_RESULT_FILTERS">
                                        <li class="normalLinks">
                                            <a id="customizeScannerSeveritiesLink" href="<spring:url value="/customize/scannerSeverities" htmlEscape="true"/>">Scanner Severities</a>
                                        </li>
                                    </security:authorize>

                                    <security:authorize ifAllGranted="ROLE_CAN_MANAGE_TAGS">
                                        <li class="normalLinks">
                                            <a id="tagsLink" href="<spring:url value="/configuration/tags" htmlEscape="true"/>">Tags</a>
                                        </li>
                                    </security:authorize>

                                    <security:authorize ifAllGranted="ROLE_ENTERPRISE,ROLE_CAN_MANAGE_POLICIES">
                                        <li class="normalLinks">
                                            <a id="policiesLink" href="<spring:url value="/configuration/policies" htmlEscape="true"/>">Policies</a>
                                        </li>
                                    </security:authorize>
                                </ul>
                            </li>
                        </security:authorize>

                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS,ROLE_CAN_MANAGE_GRC_TOOLS,ROLE_CAN_MANAGE_REMOTE_PROVIDERS, ROLE_CAN_MANAGE_SCAN_AGENTS, ROLE_CAN_MANAGE_WAFS, ROLE_CAN_MANAGE_SYSTEM_SETTINGS,ROLE_CAN_MANAGE_CUSTOM_CWE_TEXT, ROLE_CAN_MANAGE_SCAN_RESULT_FILTERS, ROLE_CAN_MANAGE_TAGS,ROLE_CAN_MANAGE_POLICIES, ROLE_CAN_MODIFY_VULNERABILITIES">
                            <li class="divider" role="presentation"></li>
                        </security:authorize>

                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_SYSTEM_SETTINGS,ROLE_CAN_MANAGE_USERS,ROLE_CAN_MANAGE_ROLES,ROLE_CAN_MANAGE_GROUPS, ROLE_CAN_MANAGE_API_KEYS, ROLE_CAN_MANAGE_EMAIL_REPORTS">

                                <li class="dropdown-submenu left pull-left normalLinks">
                                    <ul class="dropdown-menu" style="text-align:right; left: -177px;" tabindex="-1">
                                        <security:authorize ifAllGranted="ROLE_CAN_MANAGE_SYSTEM_SETTINGS">
                                            <li class="normalLinks">
                                                <a id="configureDefaultsLink" href="<spring:url value="/configuration/settings" htmlEscape="true"/>">System Settings</a>
                                            </li>
                                        </security:authorize>
                                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS">
                                            <li class="normalLinks">
                                                <a id="manageUsersLink" href="<spring:url value="/configuration/users" htmlEscape="true"/>">Users</a>
                                            </li>
                                        </security:authorize>
                                        <security:authorize ifAllGranted="ROLE_ENTERPRISE,ROLE_CAN_MANAGE_ROLES">
                                            <li class="normalLinks">
                                                <a id="manageRolesLink" href="<spring:url value="/configuration/roles" htmlEscape="true"/>">Roles</a>
                                            </li>
                                        </security:authorize>
                                        <security:authorize ifAllGranted="ROLE_ENTERPRISE,ROLE_CAN_MANAGE_GROUPS">
                                            <li class="normalLinks">
                                                <a id="manageGroupsLink" href="<spring:url value="/configuration/groups" htmlEscape="true"/>">Groups</a>
                                            </li>
                                        </security:authorize>
                                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_API_KEYS">
                                            <li class="normalLinks">
                                                <a id="apiKeysLink" href="<spring:url value="/configuration/keys" htmlEscape="true"/>">API Keys</a>
                                            </li>
                                        </security:authorize>

                                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_EMAIL_REPORTS">
                                            <li class="normalLinks">
                                                <a id="emailReportConfiguration" href="<spring:url value="/configuration/scheduledEmailReports" htmlEscape="true"/>">Email Reports</a>
                                            </li>
                                        </security:authorize>

                                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_EMAIL_REPORTS">
                                            <li class="normalLinks">
                                                <a id="emailListsLink" href="<spring:url value="/configuration/emailLists" htmlEscape="true"/>">Email Lists</a>
                                            </li>
                                        </security:authorize>
                                    </ul>
                                    <a tabindex="-1" href="#" id="adminLink">Administration</a>
                                </li>
						    </security:authorize>
                            <security:authorize ifAnyGranted="ROLE_ENTERPRISE">
                                <li class="normalLinks">
                                    <a id="historyLink" href="<spring:url value="/history" htmlEscape="true"/>">History</a>
                                </li>
                            </security:authorize>
                            <li class="normalLinks">
                                <a id="viewDownloadPageLink" href="<spring:url value="/configuration/download" htmlEscape="true"/>">Download Tools</a>
                            </li>
                            <security:authorize ifAnyGranted="ROLE_CAN_VIEW_ERROR_LOGS">
                                <li class="normalLinks">
                                    <a id="viewLogsLink" href="<spring:url value="/configuration/logs" htmlEscape="true"/>">Error Messages</a>
                                </li>
                            </security:authorize>
                            <li class="normalLinks">
                                <a id="viewAboutPageLink" href="<spring:url value="/about" htmlEscape="true"/>">About</a>
                            </li>
                        </ul>
				   </div>
				</td>
			</tr>
		</tbody>
	</table>
</div>
