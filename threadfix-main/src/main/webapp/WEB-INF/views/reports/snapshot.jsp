<div ng-controller="SnapshotReportController">

    <div class="vuln-tree">
        <select ng-change="loadReport()" style="margin-bottom: 0" class="reportTypeSelect" id="reportSnapshotSelect" ng-model="reportId">
            <option ng-selected="reportId === option.id" ng-repeat="option in snapshotOptions" value="{{ option.id }}">
                {{ option.name }}
            </option>
        </select>
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>
        <div ng-show="snapshotActive" id="pointInTimeDiv">

            <!-- Point In Time report -->
            <d3-pointintime ng-show="pointInTimeData && reportId == 2" data="pointInTimeData" label="title" update-tree="updateTree(severity)" export-report-id="exportReportId"></d3-pointintime>

            <!-- Vulnerability Progress By Type report -->
            <%@ include file="progressByVulnerability.jsp"%>
            <d3-hbars ng-show="topAppsData && reportId == 10" data="topAppsData" label = "title" width="670" height="612" margin="margin" export-report-id="exportReportId"></d3-hbars>
        </div>
    </div>

    <div id="snapshotFilterDiv" class="filter-controls">
        <h3>Filters</h3>

        <tabset ng-init="showFilterSections = true">
            <tab heading="Filters" ng-click="$parent.showFilterSections = true; $parent.showSavedFilters = false">
            </tab>
            <tab heading="Load Filters" ng-click="$parent.showFilterSections = false; $parent.showSavedFilters = true">
            </tab>
        </tabset>

        <%@ include file="filter.jsp" %>

    </div>

    <div id="vulnListDiv" ng-show="reportId == 2">
        <%@ include file="/WEB-INF/views/vulnerabilities/vulnSearchTree.jsp"%>
    </div>

</div>


