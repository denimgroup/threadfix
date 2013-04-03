<%@ include file="/common/taglibs.jsp"%>

<div id="logoBar"></div>
<div id="logo">
	<a  href="<spring:url value="/dashboard" htmlEscape="true"/>">
		<img src="<%=request.getContextPath()%>/images/hdr-threadfix-logo.png" class="transparent_png" alt="Threadfix" />
	</a>
</div>
<div id="loginInfo">
	<table style="width:100%">
		<tr>
			<td id="logout" style="padding-right:15px">
				<spring:message code="user.status"/>
				<security:authentication property="principal.username"/> | <a id="toggleHelpLink" href="javascript:toggleHelp()" >Toggle Help</a> |
				<strong><a id="logoutLink" href="<spring:url value="/j_spring_security_logout" htmlEscape="true" />">
					<spring:message code="user.logout"/>
				</a></strong>
			</td>
		</tr>
	</table>
</div>
<div id="menu">
	<table>
		<tbody>
			<tr>
				<security:authorize ifNotGranted="ROLE_CAN_GENERATE_REPORTS">
					<td id="tab-spaces" style="width:110px;background:none;"></td>
				</security:authorize>
				<td id="tab-apps" style="width: 90px;">
					<a id="orgHeader" href="<spring:url value="/organizations" htmlEscape="true"/>">Teams</a>
				</td>
				<td id="tab-wafs" style="width: 90px;">
					<a id="wafsHeader" href="<spring:url value="/wafs" htmlEscape="true"/>">Scans</a>
				</td>
				<security:authorize ifAnyGranted="ROLE_CAN_GENERATE_REPORTS">
					<td id="tab-reports" style="width: 110px;">
						<a id="reportsHeader" href="<spring:url value="/reports" htmlEscape="true"/>">Reports</a>
					</td>
				</security:authorize>
				<td id="tab-config" style="width: 150px;">
					<div class="dropdown normalLinks">
						<a id="configurationHeader" href="#">Administration</a>
						<ul style="text-align:left" class="dropdown-menu" aria-labelledby="configurationHeader" role="menu">
							<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_API_KEYS">
							    <li class="normalLinks">
							    	<a id="apiKeysLink" href="<spring:url value="/configuration/keys" htmlEscape="true"/>">API Keys</a>
							    </li>
						    </security:authorize>
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
						    	<a id="changePasswordLink" href="<spring:url value="/configuration/users/password" htmlEscape="true"/>">Change My Password</a>
						    </li>
							<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS,ROLE_CAN_MANAGE_ROLES,ROLE_CAN_VIEW_ERROR_LOGS">
								<li class="divider" role="presentation"></li>
					
							    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS">
								<li class="normalLinks">
									<a id="manageUsersLink" href="<spring:url value="/configuration/users" htmlEscape="true"/>">Manage Users</a>
								</li>
								</security:authorize>
								<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_ROLES">
						 		<li class="normalLinks">
									<a id="manageRolesLink" href="<spring:url value="/configuration/roles" htmlEscape="true"/>">Manage Roles</a>
								</li>
								</security:authorize>
								<security:authorize ifAnyGranted="ROLE_CAN_VIEW_ERROR_LOGS">
								<li class="normalLinks">
									<a id="viewLogsLink" href="<spring:url value="/configuration/logs" htmlEscape="true"/>">View Error Logs</a>
								</li>
								</security:authorize>
								<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS">
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
	<script>
		$("#tab-config").bind({
			mouseenter : function(e) {
				$("#configurationHeader").dropdown('toggle');
			},
			mouseleave : function(e) {
				$("#configurationHeader").dropdown('toggle');
			}
		});
	</script>
</div>