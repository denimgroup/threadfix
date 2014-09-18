<div ng-controller="ReportFilterController">

    <div ng-show="trendingActive || comparisonActive" class="vuln-tree">
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>
        <div ng-show="trendingActive">
            <d3-trending data="trendingScansData" label="title"></d3-trending>
        </div>
        <div ng-show="comparisonActive">
            <table id="scanComparison">
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

</div>


