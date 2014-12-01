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
        <%@ include file="filter.jsp" %>
    </div>


</div>


