<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Reports</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/report-page-controller.js"></script>
</head>

<body id="reports">

    <spring:url value="" var="emptyUrl"/>

    <div ng-controller="ReportPageController"
         ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'">

        <h2>Reports</h2>

        <tabset>
            <tab ng-repeat="tab in tabs" heading="{{tab.title}}" active="tab.active" disabled="tab.disabled" ng-click="updateOptions(tab)"></tab>
        </tabset>

        <span ng-show="teams">
            <select style="margin-bottom: 0" class="reportTypeSelect" id="reportSelect" ng-model="reportId">
                <option ng-repeat="option in options" value="{{ option.id }}">
                    {{ option.name }}
                </option>
            </select>

            Team
            <select style="margin-bottom: 0" id="teamSelect" ng-model="team" ng-change="updateApplications()" ng-options="team.name for team in teams"></select>

            Application
            <select style="margin-bottom: 0" ng-hide="applications" disabled="disabled">
                <option>All</option>
            </select>
            <select style="margin-bottom: 0" ng-show="applications" id="applicationSelect" ng-model="application" ng-options="app.name for app in applications"></select>
        </span>
        <span style="float:right" ng-show="loading" class="spinner dark"></span>

        <div style="margin-top: 10px" id="successDiv">
            <c:if test="${ not hasVulnerabilities }">
                <div class="alert alert-danger" style="margin-top:10px">
                    <button class="close" data-dismiss="alert" type="button">�</button>
                    <strong>No Vulnerabilities found.</strong> Upload a scan and try again.
                    <spring:url value="/organizations" var="teamsPageUrl"/>
                    <a href="${ teamsPageUrl }">Get Started</a>
                </div>
            </c:if>

            <div ng-show="noDataFound">
                <%@include file="/WEB-INF/views/reports/emptyReport.jspf" %>
            </div>
            <div ng-show="reportHTML" bind-html-unsafe="reportHTML">

            </div>
        </div>

    </div>

</body>
