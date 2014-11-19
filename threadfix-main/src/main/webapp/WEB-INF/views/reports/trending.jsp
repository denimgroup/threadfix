<div ng-controller="TrendingReportController">

    <div class="vuln-tree">
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>

        <div ng-show="trendingActive">
            <d3-trending data="trendingScansData" label="title" width="670" height="612" margin="margin"
                         start-date="trendingStartDate" end-date="trendingEndDate" export-info="exportInfo" svg-id="title.svgId"></d3-trending>
        </div>

    </div>

    <div id="trendingFilterDiv" class="filter-controls">
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


