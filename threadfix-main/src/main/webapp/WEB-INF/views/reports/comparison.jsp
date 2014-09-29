<div ng-controller="ComparisonReportController">

    <div class="vuln-tree">
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>
        <div ng-show="comparisonActive">
            Comparison
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


