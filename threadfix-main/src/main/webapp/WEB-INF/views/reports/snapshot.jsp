<div ng-controller="SnapshotReportController">

    <div class="vuln-tree">
        <select ng-change="loadReport()" style="margin-bottom: 0" class="reportTypeSelect" id="reportSelect" ng-model="reportId">
            <option ng-selected="reportId === option.id" ng-repeat="option in snapshotOptions" value="{{ option.id }}">
                {{ option.name }}
            </option>
        </select>
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>
        <div ng-show="snapshotActive" id="pointInTimeDiv">

            <!-- Point In Time report -->
            <d3-pointintime ng-show="pointInTimeData && reportId === '2'" data="pointInTimeData" label="title" update-tree="updateTree(severity)"></d3-pointintime>

            <!-- Vulnerability Progress By Type report -->
            <%@ include file="progressByVulnerability.jsp"%>

        </div>
    </div>

    <div class="filter-controls">
        <h3>Filters</h3>

        <div>
            <%@ include file="filter.jsp" %>
        </div>

    </div>

    <div ng-show="reportId === '2'">
        <%@ include file="/WEB-INF/views/vulnerabilities/vulnSearchTree.jsp"%>
    </div>

</div>


