<div ng-controller="ReportFilterController">

    <div ng-show="trendingActive" class="vuln-tree">
        <%--<h3>--%>
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>
        <%--</h3>--%>
        <table style="text-align:center;font-weight:bold;" class="vuln-tree" ng-show="!loading">
            <tbody>
            <tr>
                <td style="font-size:20px;font-weight:bold;">
                    Trending Report
                </td>
            </tr>
            <tr ng-show="title.teams">
                <td>Team: {{title.teams}}</td>
            </tr>
            <tr ng-show="title.apps">
                <td>Application: {{title.apps}}</td>
            </tr>
            </tbody>
        </table>
        <d3-trending data="trendingScansData" label="title"></d3-trending>
    </div>

    <div class="filter-controls">
        <h3>Filters</h3>

        <div >
            <%@ include file="filter.jsp" %>
        </div>

    </div>

</div>


