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

        <select class="reportTypeSelect" id="reportSelect" ng-model="reportId">
            <option ng-repeat="option in options" value="{{ option.id }}">
                {{ option.name }}
            </option>
        </select>

        <span ng-show="teams">
            Team
            <select id="teamSelect" ng-model="organizationId" ng-change="updateApplications()">
                <option value="-1" ng-selected="{{ teams.length === -1 }}">All</option>
                <option ng-repeat="team in teams" value="{{ team }}">
                    {{ team.name }}
                </option>
            </select>

            Application
            <select id="applicationSelect" ng-model="applicationId">
                <option value="-1" ng-selected="{{ applications.length === 0 }}">All</option>
                <option ng-repeat="app in applications" value="{{ app.id }}">
                    {{ app.name }}
                </option>
            </select>
        </span>


        <span id="appDropDown">
            <a id="csvLink" class="btn btn-primary" ng-click="triggerCSVDownload()">
                Export CSV
            </a>

            <a id="pdfLink" ng-click="triggerPDFDownload()">
                Export PDF
            </a>
        </span>

        <div id="successDiv">
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
            <div ng-show="loading" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
            <div ng-show="reportHTML" bind-html-unsafe="reportHTML">

            </div>
        </div>

    </div>

</body>
