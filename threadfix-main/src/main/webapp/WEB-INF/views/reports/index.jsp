<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Analytics</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/report-page-controller.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/vuln-search-controller.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/generic-modal-controller.js"></script>
</head>

<body id="reports">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="../applications/forms/vulnCommentForm.jsp"%>

    <div ng-controller="ReportPageController"
         ng-init="firstReportId = '<c:out value="${ firstReport }"/>';
                 firstAppId = '<c:out value="${ firstAppId }"/>';
                 firstTeamId = '<c:out value="${ firstTeamId }"/>'">

        <h2>Analytics</h2>

        <tabset>
            <tab ng-repeat="tab in tabs" heading="{{tab.title}}" active="tab.active" disabled="tab.disabled" ng-click="updateOptions(tab)"></tab>
            <tab heading="Vulnerability Search" ng-click="loadVulnSearch()">
                <%@ include file="../vulnerabilities/vulnSearchControls.jsp" %>
            </tab>
        </tabset>

        <span ng-show="teams && !vulnSearch">
            <select ng-change="loadReport()" style="margin-bottom: 0" class="reportTypeSelect" id="reportSelect" ng-model="reportId">
                <option ng-selected="reportId === option.id" ng-repeat="option in options" value="{{ option.id }}">
                    {{ option.name }}
                </option>
            </select>

            Team
            <select style="margin-bottom: 0" id="teamSelect" ng-model="teamId" ng-change="updateApplications()">
                <option ng-selected="teamId === team.id" ng-repeat="team in teams" value="{{ team.id }}">
                    {{ team.name }}
                </option>
            </select>

            Application
            <select style="margin-bottom: 0" ng-hide="applications" disabled="disabled">
                <option>All</option>
            </select>
            <select style="margin-bottom: 0"
                    ng-change="loadReport()"
                    ng-show="applications"
                    id="applicationSelect"
                    ng-model="applicationId">
                <option ng-selected="applicationId === application.id" ng-repeat="application in applications" value="{{ application.id }}">
                    {{ application.name }}
                </option>
            </select>
        </span>
        <span style="float:right" ng-show="loading" class="spinner dark"></span>

        <div ng-hide="vulnSearch" style="margin-top: 10px" id="successDiv">
            <c:if test="${ not hasVulnerabilities }">
                <div class="alert alert-danger" style="margin-top:10px">
                    <button class="close" data-dismiss="alert" type="button">&times;</button>
                    <strong>No Vulnerabilities found.</strong> Upload a scan and try again.
                    <spring:url value="/teams" var="teamsPageUrl"/>
                    <a href="${ teamsPageUrl }">Get Started</a>
                </div>
            </c:if>

            <div ng-show="noDataFound">
                <%@include file="/WEB-INF/views/reports/emptyReport.jspf" %>
            </div>
            <div ng-show="reportHTML" tf-bind-html-unsafe="reportHTML">

            </div>
            <%@ include file="/WEB-INF/views/reports/scannerComparisonByVulnerability.jsp"%>
            <%@ include file="/WEB-INF/views/reports/vulnerabilityList.jsp"%>
        </div>

    </div>

</body>
