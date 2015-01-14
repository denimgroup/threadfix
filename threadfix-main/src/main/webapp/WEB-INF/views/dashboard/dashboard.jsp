<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Dashboard</title>
	<cbs:cachebustscript src="/scripts/dashboard-controller.js"/>
	<cbs:cachebustscript src="/scripts/left-report-controller.js"/>
	<cbs:cachebustscript src="/scripts/right-report-controller.js"/>
	<cbs:cachebustscript src="/scripts/report/vuln-summary-modal-controller.js"/>
</head>

<body class="dashboard">
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="/WEB-INF/views/reports/vulnSummaryModal.jsp" %>

	<h2>Dashboard</h2>
	
	<spring:url value="/teams" var="teamsUrl"/>
	
	<c:if test="${ empty teams }">
		<security:authorize ifAnyGranted="ROLE_CAN_MANAGE_TEAMS">
		    <div class="alert" ng-show="!dismissNoTeamsFound">
			    <button type="button" class="close" ng-click="dismissNoTeamsFound = true">&times;</button>
			    <strong>No teams found!</strong> To upload scans, first you need to create teams and applications.  
			    <a href="<c:out value="${ teamsUrl }"/>#myTeamModal">
			    	Get started
			    </a>
	  	 	</div>
	  	</security:authorize>
  	 	
		<security:authorize ifNotGranted="ROLE_READ_ACCESS">
			<div class="alert alert-error">
				You don't have permission to access any ThreadFix applications or to create one for yourself. 
				Contact your administrator to get help.
			</div>
		</security:authorize>
	</c:if>

    <div ng-controller="DashboardController" class="container-fluid">

        <c:if test="${ not empty teams }">
            <security:authorize ifAnyGranted="ROLE_READ_ACCESS, ROLE_CAN_GENERATE_REPORTS">
				<div class="row-fluid">
					<%@include file="/WEB-INF/views/applications/widgets/vulnerabilityTrending.jsp"%>
					<%@include file="/WEB-INF/views/applications/widgets/mostVulnerableApps.jsp"%>
			  	</div>
                <div class="row-fluid">
                    <div class="row-fluid" style="padding-top:20px;">
                        <%@include file="/WEB-INF/views/applications/widgets/recentUploads.jsp"%>
                        <%@include file="/WEB-INF/views/applications/widgets/recentComments.jsp"%>
                    </div>
                </div>
            </security:authorize>
        </c:if>

    </div>
</body>
