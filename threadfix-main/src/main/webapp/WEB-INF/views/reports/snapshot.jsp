<div ng-controller="SnapshotReportController">

    <div class="vuln-tree">
        <select ng-change="loadReport()" style="margin-bottom: 0" class="reportTypeSelect" id="reportSnapshotSelect" ng-model="reportId">
            <option ng-selected="reportId === option.id" ng-repeat="option in snapshotOptions" value="{{ option.id }}">
                {{ option.name }}
            </option>
        </select>
        <span class="spinner-div">
            <span id="loadingSpinner" ng-if="loading" class="spinner dark"></span>
        </span>
        <div ng-show="snapshotActive" id="pointInTimeDiv">

            <!-- Point In Time report -->
            <d3-pointintime ng-show="pointInTimeData && reportId == PIT_Report_Id" data="pointInTimeData"
                            label="title" export-report-id="exportInfo"></d3-pointintime>

            <!-- Vulnerability Progress By Type report -->
            <%@ include file="progressByVulnerability.jsp"%>

            <!-- Most Vulnerable Application -->
            <d3-hbars ng-show="topAppsData && reportId == MVA_Report_Id" data="topAppsData" label = "title"
                      width="670" height="612" margin="margin" export-report-id="exportInfo"></d3-hbars>
        </div>
    </div>

    <div id="snapshotFilterDiv" class="filter-controls">
        <%@ include file="filter.jsp" %>
    </div>

    <div id="vulnListDiv" ng-show="reportId == PIT_Report_Id || reportId == OWASP_Report_Id">
        <%@ include file="/WEB-INF/views/vulnerabilities/vulnSearchTree.jsp"%>
    </div>

    <div id="render_me">
        <table id="customers" class="table table-striped" >
            <thead>
            <tr class='warning'>
                <th>Country</th>
                <th>Population</th>
                <th>Date</th>
                <th>%ge</th>
            </tr>
            </thead>
            <tbody>
            <tr>
                <td>Chinna</td>
                <td>1,363,480,000</td>
                <td>March 24, 2014</td>
                <td>19.1</td>
            </tr>
            <tr>
                <td>India</td>
                <td>1,241,900,000</td>
                <td>March 24, 2014</td>
                <td>17.4</td>
            </tr>
            <tr>
                <td>United States</td>
                <td>317,746,000</td>
                <td>March 24, 2014</td>
                <td>4.44</td>
            </tr>
            <tr>
                <td>Indonesia</td>
                <td>249,866,000</td>
                <td>July 1, 2013</td>
                <td>3.49</td>
            </tr>
            <tr>
                <td>Brazil</td>
                <td>201,032,714</td>
                <td>July 1, 2013</td>
                <td>2.81</td>
            </tr>
            </tbody>
        </table>
    </div>

</div>


