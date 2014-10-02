<div ng-controller="TrendingReportController">

    <div class="vuln-tree">
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>

        <div ng-show="trendingActive">
            <d3-trending data="trendingScansData" label="title" width="670" height="612" margin="margin"></d3-trending>
        </div>

    </div>

    <div class="filter-controls">
        <h3>Filters</h3>

        <div >
            <%@ include file="filter.jsp" %>
        </div>

    </div>

</div>


