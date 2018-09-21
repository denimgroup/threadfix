<div ng-controller="SnapshotReportController">

    <div class="vuln-tree">
        <select ng-change="loadReport()" style="margin-bottom: 0; width:auto" class="reportTypeSelect" id="reportSnapshotSelect" ng-model="reportId">
            <option ng-selected="reportId === option.id" ng-repeat="option in snapshotOptions" value="{{ option.id }}">
                {{ option.name }}
            </option>
        </select>
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>
        <div ng-show="snapshotActive" id="pointInTimeDiv">

            <!-- Point In Time report -->
            <d3-point-in-time ng-if="reportId == PIT_Report_Id"
                              data="vulnTree"
                              <%--data="pointInTimeData"--%>
                            label="title" average-ages = "averageAges" generic-severities = "genericSeverities"></d3-point-in-time>

            <!-- Vulnerability Progress By Type report -->
            <%@ include file="progressByVulnerability.jsp"%>

            <!-- Most Vulnerable Application -->
            <d3-hbars ng-show="reportId == MVA_Report_Id" data="topAppsData" label = "title"
                      width="670" height="612" margin="margin" export-report-id="exportInfo"></d3-hbars>

            <!-- Portfolio report -->
            <%@ include file="portfolioReport.jsp"%>

            <!-- Scanner Comparison report -->
            <%@ include file="scannerComparison.jsp"%>
        </div>
    </div>

    <div id="snapshotFilterDiv" class="filter-controls">
        <%@ include file="filter.jsp" %>
    </div>

    <div id="vulnListDiv" ng-show="reportId == PIT_Report_Id || reportId == OWASP_Report_Id || reportId == DISA_STIG_Report_Id">
        <%@ include file="/WEB-INF/views/vulnerabilities/vulnSearchTree.jsp"%>
    </div>

</div>


