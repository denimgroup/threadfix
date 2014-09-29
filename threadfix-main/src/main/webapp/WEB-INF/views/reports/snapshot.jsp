<div ng-controller="SnapshotReportController">

    <div class="vuln-tree">
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>
        <div ng-show="snapshotActive" id="pointInTimeDiv">
            <d3-pointintime ng-show="pointInTimeData" data="pointInTimeData" label="title" update-tree="updateTree(severity)"></d3-pointintime>
            <table id="snapshot">
                <thead></thead>
                <tbody></tbody>
            </table>
        </div>
    </div>

    <div class="filter-controls">
        <h3>Filters</h3>

        <div >
            <%@ include file="filter.jsp" %>
        </div>

    </div>

    <%@ include file="/WEB-INF/views/vulnerabilities/vulnSearchTree.jsp"%>

</div>


