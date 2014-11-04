<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Analytics</title>
    <cbs:cachebustscript src="/scripts/report/directives/d3-point-in-time.js"/>
    <cbs:cachebustscript src="/scripts/report/report-filter-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/report-services.js"/>
    <cbs:cachebustscript src="/scripts/report/trending-report-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/snapshot-report-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/comparison-report-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/vuln-summary-modal-controller.js"/>
    <cbs:cachebustscript src="/scripts/report-page-controller.js"/>
    <cbs:cachebustscript src="/scripts/vuln-search-controller.js"/>
    <cbs:cachebustscript src="/scripts/generic-modal-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
</head>

<body id="reports">

    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="../applications/forms/vulnCommentForm.jsp"%>
    <%@ include file="/WEB-INF/views/reports/vulnSummaryModal.jsp" %>

    <div ng-controller="ReportPageController"
         ng-init="firstReportId = '<c:out value="${ firstReport }"/>';
                 firstAppId = '<c:out value="${ firstAppId }"/>';
                 firstTeamId = '<c:out value="${ firstTeamId }"/>'">

        <h2>Analytics</h2>

        <tabset>
            <tab heading="Trending" ng-click="loadTrending()" active="trendingActive">
                <%@ include file="trending.jsp" %>
            </tab>
            <tab heading="Snapshot" ng-click="loadSnapshot()" active="snapshotActive">
                <%@ include file="snapshot.jsp" %>
            </tab>
            <%--<tab ng-repeat="tab in tabs" heading="{{tab.title}}" active="tab.active" disabled="tab.disabled" ng-click="updateOptions(tab)"></tab>--%>
            <tab heading="Vulnerability Search" ng-click="loadVulnSearch()" active="showVulnTab">
                <%@ include file="../vulnerabilities/vulnSearchControls.jsp" %>
            </tab>
        </tabset>

        <span style="float:right" ng-show="loading" class="spinner dark"></span>

        <div style="margin-top: 10px" id="successDiv">
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
        </div>

    </div>

</body>
