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
				<td class="clickInsideLink" id="tab-dashboard" style="width: 130px;">
					<a id="dashboardHeader" href="<spring:url value="/dashboard" htmlEscape="true"/>">Dashboard</a>
				</td>
				<td class="clickInsideLink" id="tab-apps" style="width: 120px;">
					<a id="orgHeader" href="<spring:url value="/organizations" htmlEscape="true"/>">Applications</a>
				</td>
				<td class="clickInsideLink" id="tab-scans" style="width: 90px;">
					<a id="scansHeader" href="<spring:url value="/scans" htmlEscape="true"/>">Scans</a>
				</td>
				<security:authorize ifAnyGranted="ROLE_CAN_GENERATE_REPORTS">
					<td class="clickInsideLink" id="tab-reports" style="width: 110px;">
						<a id="reportsHeader" href="<spring:url value="/reports" htmlEscape="true"/>">Reports</a>
					</td>
				</security:authorize>
				<td id="tab-user" style="width: 130px;">
					<div class="dropdown normalLinks">
					<div data-toggle="dropdown" data-target="#" style="height:32px;text-align:center;">
						<div style="display:inline-block;margin-top:6px;">
						<a id="tabUserAnchor" href="#">
							<i class="icon-user icon-white"></i> <security:authentication property="principal.username"/>
							<span id="header-caret" class="caret-down" style="padding-left:0px"></span>
						</a>
						</div>
				  	 </div>
					<ul id="configurationHeader" class="dropdown-menu pull-right config-header" style="text-align:right;" aria-labelledby="configurationHeader" role="menu">
						
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
							<a id="toggleHelpLink" href="javascript:toggleHelp()">Toggle Help</a>
						</li>
						<li class="normalLinks">
							<a id="logoutLink" href="<spring:url value="/j_spring_security_logout" htmlEscape="true" />">
								<spring:message code="user.logout"/>
							</a>
						</li>
					</ul>
				   </div>
				</td>
				<td id="tab-config" style="width: 30px;padding-left:0px;">
					
					<div class="dropdown normalLinks">
					<div data-toggle="dropdown" data-target="#" style="height:32px;text-align:center;">
						<div style="display:inline-block;margin-top:6px;">
						<a id="tabConfigAnchor" href="#">
							<i class="icon-cog icon-white"></i>
						</a>
						</div>
				  	 </div>
					<ul id="configurationHeader" class="dropdown-menu config-header" style="text-align:left;" aria-labelledby="configurationHeader" role="menu">
						<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_API_KEYS">
						    <li class="normalLinks">
						    	<a id="apiKeysLink" href="<spring:url value="/configuration/keys" htmlEscape="true"/>">API Keys</a>
						    </li>
					    </security:authorize>
					    <li class="normalLinks">
						    	<a id="scanQueueLink" href="<spring:url value="/configuration/scanqueue" htmlEscape="true"/>">Scan Queue</a>
						</li>
						<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_WAFS">
						    <li class="normalLinks">
						    	<a id="wafsLink" href="<spring:url value="/wafs" htmlEscape="true"/>">WAFs</a>
						    </li>
					    </security:authorize>
					    <li class="normalLinks">
					    	<a id="defectTrackersLink" href="<spring:url value="/configuration/defecttrackers" htmlEscape="true"/>">Defect Trackers</a>
					    </li>
					    <li class="normalLinks">
					    	<a id="remoteProvidersLink" href="<spring:url value="/configuration/remoteproviders" htmlEscape="true"/>">Remote Providers</a>
					    </li>
					    <li class="normalLinks">
					    	<a id="updateChannelVulnLink" href="<spring:url value="/scanplugin/index" htmlEscape="true"/>">Scanner Plugin</a>
					    </li>						
						<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS,ROLE_CAN_MANAGE_ROLES,ROLE_CAN_VIEW_ERROR_LOGS">
							<li class="divider" role="presentation"></li>
				
						    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS">
							<li class="normalLinks">
								<a id="manageUsersLink" href="<spring:url value="/configuration/users" htmlEscape="true"/>">Manage Users</a>
							</li>
							</security:authorize>
							<security:authorize ifAnyGranted="ROLE_ENTERPRISE">
							<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_ROLES">
					 		<li class="normalLinks">
								<a id="manageRolesLink" href="<spring:url value="/configuration/roles" htmlEscape="true"/>">Manage Roles</a>
							</li>
							</security:authorize>
							</security:authorize>
							<security:authorize ifAnyGranted="ROLE_CAN_MODIFY_VULNERABILITIES">
					 		<li class="normalLinks">
								<a id="vulnFiltersLink" href="<spring:url value="/configuration/filters" htmlEscape="true"/>">Manage Filters</a>
							</li>
							</security:authorize>
							<security:authorize ifAnyGranted="ROLE_CAN_VIEW_ERROR_LOGS">
							<li class="normalLinks">
								<a id="viewLogsLink" href="<spring:url value="/configuration/logs" htmlEscape="true"/>">View Error Logs</a>
							</li>
							</security:authorize>
							<security:authorize ifAnyGranted="ROLE_ENTERPRISE">
							<li class="normalLinks">
								<a id="configureDefaultsLink" href="<spring:url value="/configuration/defaults" htmlEscape="true"/>">Configure Defaults</a>
							</li>
							</security:authorize>
						</security:authorize>
					</ul>
				   </div>
				</td>
			</tr>
		</tbody>
	</table>
</div>