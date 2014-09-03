<%--<div class="vuln-search-filter-control" style="width:900px;" ng-controller="VulnSearchController">--%>
<div ng-controller="ReportFilterController">
    <div ng-show="trendingActive" class="vuln-tree">
        <d3-trending data="trendingScansData"></d3-trending>
    </div>
    <div class="filter-controls">
        <h3>Filters</h3>

        <div >
            <%@ include file="filter.jsp" %>
        </div>

    </div>

</div>


