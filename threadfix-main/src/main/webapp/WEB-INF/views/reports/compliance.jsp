<div ng-controller="ComplianceReportController">

    <div class="vuln-tree">
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>

        <div ng-show="complianceActive">
            <d3-trending data="trendingScansData" label="title" width="670" height="400" margin="margin" table-info="tableInfo"></d3-trending>
        </div>

        <div id="complianceTable">
            <table>
                <thead></thead>
                <tbody></tbody>
            </table>
        </div>

    </div>

    <div id="complianceFilterDiv" class="filter-controls">
        <h3>Filters</h3>

        <tabset ng-init="showFilterSections = true">
            <tab heading="Filters" ng-click="$parent.showFilterSections = true; $parent.showSavedFilters = false">
            </tab>
            <tab heading="Load Filters" ng-click="$parent.showFilterSections = false; $parent.showSavedFilters = true">
            </tab>
        </tabset>

        <%@ include file="filter.jsp" %>
    </div>


</div>


