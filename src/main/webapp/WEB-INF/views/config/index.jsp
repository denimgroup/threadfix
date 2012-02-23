<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Configuration</title>
</head>

<body id="config">
	<h2>Configuration</h2>
	
	<ul class="squareList" style="padding-left:15px">
	    <li>
	    	<a id="defectTrackersLink" href="<spring:url value="configuration/defecttrackers" htmlEscape="true"/>">Defect Trackers</a>
	    </li>
	    <li>
	    	<a id="jobStatusesLink" href="<spring:url value="/jobs/all" />">Job Statuses</a>
	    </li>
    <security:authorize ifAnyGranted="ROLE_ADMIN">
		<li>
			<a id="manageUsersLink" href="<spring:url value="configuration/users" htmlEscape="true"/>">Manage Users</a>
		</li>
	</security:authorize>
	    <li>
	    	<a id="remoteProvidersLink" href="<spring:url value="configuration/remoteproviders" htmlEscape="true"/>">Remote Providers</a>
	    </li>
		<li>
	    	<a id="whiteHatLink" href="<spring:url value="configuration/whitehat" htmlEscape="true"/>">WhiteHat Sentinel</a>
	    </li>
		<li>
	    	<a id="apiKeysLink" href="<spring:url value="configuration/keys" htmlEscape="true"/>">API Keys</a>
	    </li>
	</ul>
</body>