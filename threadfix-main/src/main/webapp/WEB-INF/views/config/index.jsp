<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Configuration</title>
</head>

<body id="config">
	<h2>Configuration</h2>
	
	<ul class="squareList" style="padding-left:15px">
		<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_API_KEYS">
		    <li>
		    	<a id="apiKeysLink" href="<spring:url value="configuration/keys" htmlEscape="true"/>">API Keys</a>
		    </li>
	    </security:authorize>
	    <li>
	    	<a id="defectTrackersLink" href="<spring:url value="configuration/defecttrackers" htmlEscape="true"/>">Defect Trackers</a>
	    </li>
	    <%--<security:authorize ifAnyGranted="ROLE_CAN_VIEW_JOB_STATUSES">--%>
		    <%--<li>--%>
		    	<%--<a id="jobStatusesLink" href="<spring:url value="/jobs/all" />">Job Statuses</a>--%>
		    <%--</li>--%>
	    <%--</security:authorize>--%>
	    <li>
	    	<a id="remoteProvidersLink" href="<spring:url value="configuration/remoteproviders" htmlEscape="true"/>">Remote Providers</a>
	    </li>
	    <li>
	    	<a id="changePasswordLink" href="<spring:url value="configuration/users/password" htmlEscape="true"/>">Change My Password</a>
	    </li>
	</ul>

	<br>

	<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS,ROLE_CAN_MANAGE_ROLES,ROLE_CAN_VIEW_ERROR_LOGS">
	<h2>Administration</h2>
	</security:authorize>

	<ul class="squareList" style="padding-left:15px">
	    <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS">
		<li>
			<a id="manageUsersLink" href="<spring:url value="configuration/users" htmlEscape="true"/>">Manage Users</a>
		</li>
		</security:authorize>
		<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_ROLES">
 		<li>
			<a id="manageRolesLink" href="<spring:url value="configuration/roles" htmlEscape="true"/>">Manage Roles</a>
		</li>
		</security:authorize>
		<security:authorize ifAnyGranted="ROLE_CAN_VIEW_ERROR_LOGS">
		<li>
			<a id="viewLogsLink" href="<spring:url value="configuration/logs" htmlEscape="true"/>">View Error Messages</a>
		</li>
		</security:authorize>
		<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_USERS">
		<li>
			<a id="configureDefaultsLink" href="<spring:url value="configuration/defaults" htmlEscape="true"/>">Configure Defaults</a>
		</li>
		</security:authorize>
	</ul>
	
	
</body>