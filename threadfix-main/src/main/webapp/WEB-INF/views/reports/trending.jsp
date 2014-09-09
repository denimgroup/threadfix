<div ng-controller="ReportFilterController">

    <div ng-show="trendingActive" class="vuln-tree">
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>
        <d3-trending data="trendingScansData" label="title"></d3-trending>
    </div>

    <div class="filter-controls">
        <h3>Filters</h3>

        <div >
            <%@ include file="filter.jsp" %>
        </div>

    </div>

</div>


