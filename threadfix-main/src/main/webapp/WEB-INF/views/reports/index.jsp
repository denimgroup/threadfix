<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Analytics</title>
    <cbs:cachebustscript src="/scripts/report/directives/d3-point-in-time.js"/>
    <cbs:cachebustscript src="/scripts/report/report-filter-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/report-services.js"/>
    <cbs:cachebustscript src="/scripts/report/trending-report-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/snapshot-report-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/compliance-report-controller.js"/>
    <cbs:cachebustscript src="/scripts/report/vuln-summary-modal-controller.js"/>
    <cbs:cachebustscript src="/scripts/report-page-controller.js"/>
    <cbs:cachebustscript src="/scripts/vuln-search-controller.js"/>
    <cbs:cachebustscript src="/scripts/generic-modal-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
    <cbs:cachebustscript src="/scripts/vulnerability-comments-table-controller.js"/>
    <cbs:cachebustscript src="/scripts/vuln-search-tree-controller.js"/>

    <cbs:cachebustscript src="/scripts/report/canvg.js"/>
    <cbs:cachebustscript src="/scripts/report/rgbcolor.js"/>
    <c:if test="${not empty reportJsPaths}">
        <c:forEach items="${reportJsPaths}" var="reportJs">
            <script type="text/javascript" src="${reportJs}"></script>
        </c:forEach>
    </c:if>

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

    <div>
        <c:if test="${ hasVulnerabilities }">
            <tabset>
                <tab id="trendingTab" heading="Trending" ng-click="loadTrending()" active="trendingActive">
                    <%@ include file="trending.jsp" %>
                </tab>
                <tab id="snapshotTab" heading="Snapshot" ng-click="loadSnapshot()" active="snapshotActive">
                    <%@ include file="snapshot.jsp" %>
                </tab>
                <tab id="remediationTab" heading="Remediation" ng-click="loadCompliance()" active="complianceActive">
                    <div ng-controller="ComplianceReportController"
                         ng-init="remediationType = 1; graphName = 'complianceTrendingGraph'; sumTableDivId = 'complianceTable1'">
                        <%@ include file="compliance.jsp" %>
                    </div>
                </tab>
                <c:if test="${isEnterprise}">
                    <tab id="enterpriseTab" active="remediationEnterpriseActive" heading="Compliance" ng-click="loadEnterpriseRemediation()">
                        <div ng-controller="ComplianceReportController"
                             ng-init="remediationType = 2; graphName = 'complianceEnterpriseTrendingGraph'; sumTableDivId = 'complianceTable2'">
                            <%@ include file="compliance.jsp" %>
                        </div>
                    </tab>
                </c:if>
                <tab heading="Vulnerability Search" ng-click="loadVulnSearch()" active="showVulnTab">
                    <%@ include file="../vulnerabilities/vulnSearchControls.jsp" %>
                </tab>
                <c:if test="${not empty customReports}">
                    <tab id="customReportTab" heading="Custom Reports" ng-click="loadCustom()" active="customActive">
                        <%@ include file="custom.jsp" %>
                    </tab>
                </c:if>
            </tabset>

            <span style="float:right" ng-show="loading" class="spinner dark"></span>
        </c:if>
    </div>

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
