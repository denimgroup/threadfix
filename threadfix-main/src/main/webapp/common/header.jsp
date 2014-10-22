<%@ include file="/common/taglibs.jsp"%>

<div id="logoBar"></div>
<div id="logo">
	<a  href="<spring:url value="/dashboard" htmlEscape="true"/>">
		<img src="<%=request.getContextPath()%>/images/TF_logo_w_arrow_strap.png" class="transparent_png" alt="Threadfix" />
	</a>
</div>

<div id="menu" ng-controller="HeaderController">
	<table>
		<tbody>
			<tr>
				<security:authorize ifNotGranted="ROLE_CAN_GENERATE_REPORTS">
					<td id="tab-spaces" style="width:110px;background:none;"></td>
				</security:authorize>

                <spring:url value="/dashboard" htmlEscape="true" var="dashboardLink"/>
				<td class="pointer" ng-click="goTo('/dashboard')" id="tab-dashboard" style="width: 130px;">
					<a id="dashboardHeader" href="<spring:url value="/dashboard" htmlEscape="true"/>">Dashboard</a>
				</td>
				<td class="pointer" ng-click="goTo('/organizations')"  id="tab-apps" style="width: 120px;">
					<a id="orgHeader" href="<spring:url value="/teams" htmlEscape="true"/>">Teams</a>
				</td>
				<td class="pointer" ng-click="goTo('/scans')" id="tab-scans" style="width: 90px;">
					<a id="scansHeader" href="<spring:url value="/scans" htmlEscape="true"/>">Scans</a>
				</td>
				<security:authorize ifAnyGranted="ROLE_CAN_GENERATE_REPORTS">
					<td class="pointer" ng-click="goTo('/reports')" id="tab-reports" style="width: 110px;">
						<a id="reportsHeader" href="<spring:url value="/reports" htmlEscape="true"/>">Analytics</a>
					</td>
				</security:authorize>
				<td id="tab-user" style="width: 130px;">
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
						<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_API_KEYS">
						    <li class="normalLinks">
						    	<a id="apiKeysLink" href="<spring:url value="/configuration/keys" htmlEscape="true"/>">API Keys</a>
						    </li>
					    </security:authorize>
                        <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_DEFECT_TRACKERS">
                            <li class="normalLinks">
                                <a id="defectTrackersLink" href="<spring:url value="/configuration/defecttrackers" htmlEscape="true"/>">Defect Trackers</a>
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
                        <security:authorize ifAllGranted="ROLE_CAN_MANAGE_SYSTEM_SETTINGS">
                            <li class="normalLinks">
                                <a id="updateChannelVulnLink" href="<spring:url value="/scanplugin/index" htmlEscape="true"/>">Scanner Plugin</a>
                            </li>
                        </security:authorize>
                        <security:authorize ifAllGranted="ROLE_CAN_MANAGE_TAGS">
                            <li class="normalLinks">
                                <a id="tagsLink" href="<spring:url value="/configuration/tags" htmlEscape="true"/>">Tags</a>
                            </li>
                        </security:authorize>
						<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_WAFS">
						    <li class="normalLinks">
						    	<a id="wafsLink" href="<spring:url value="/wafs" htmlEscape="true"/>">WAFs</a>
						    </li>
					    </security:authorize>
						<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_SYSTEM_SETTINGS,ROLE_CAN_MANAGE_USERS,ROLE_CAN_MANAGE_ROLES,ROLE_CAN_VIEW_ERROR_LOGS">
							<li class="divider" role="presentation"></li>
                            <security:authorize ifAllGranted="ROLE_ENTERPRISE,ROLE_CAN_MANAGE_SYSTEM_SETTINGS">
                                <li class="normalLinks">
                                    <a id="configureDefaultsLink" href="<spring:url value="/configuration/settings" htmlEscape="true"/>">System Settings</a>
                                </li>
                            </security:authorize>
                            <security:authorize ifAnyGranted="ROLE_CAN_MODIFY_VULNERABILITIES">
                                <li class="normalLinks">
                                    <a id="vulnFiltersLink" href="<spring:url value="/configuration/filters" htmlEscape="true"/>">Manage Filters</a>
                                </li>
                            </security:authorize>
                            <security:authorize ifAnyGranted="ROLE_ENTERPRISE">
                                <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_ROLES">
                                    <li class="normalLinks">
                                        <a id="manageRolesLink" href="<spring:url value="/configuration/roles" htmlEscape="true"/>">Manage Roles</a>
                                    </li>
                                </security:authorize>
                            </security:authorize>
						    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS">
                                <li class="normalLinks">
                                    <a id="manageUsersLink" href="<spring:url value="/configuration/users" htmlEscape="true"/>">Manage Users</a>
                                </li>
							</security:authorize>
							<security:authorize ifAnyGranted="ROLE_CAN_VIEW_ERROR_LOGS">
                                <li class="normalLinks">
                                    <a id="viewLogsLink" href="<spring:url value="/configuration/logs" htmlEscape="true"/>">View Error Logs</a>
                                </li>
							</security:authorize>
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
