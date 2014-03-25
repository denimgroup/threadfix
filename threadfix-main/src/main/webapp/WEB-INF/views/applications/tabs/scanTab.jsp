
<tab ng-controller="ScanTableController"
     heading="{{ heading }}">

    <div ng-hide="scans" class="empty-tab-drop-area">
        <div>Drop a scan here to upload.</div>
    </div>

    <table ng-show="scans" class="table table-striped">
        <thead>
            <tr>
                <th class="first">Channel</th>
                <th>Scan Date</th>
                <c:if test="${ not canUploadScans }">
                    <th>Total Vulns</th>
                </c:if>
                <c:if test="${ canUploadScans }">
                    <th style="text-align:center">Total Vulns</th>
                    <th style="text-align:center">Hidden Vulns</th>
                    <th class="medium"></th>
                </c:if>
                <th class="medium"></th>
            </tr>
        </thead>
        <tbody>
            <tr ng-repeat="scan in scans" class="bodyRow">
                <td id="channelType{{ $index }}"> {{ scan.scannerName }} </td>
                <td>
                    {{ scan.importTime | date:'medium' }}
                </td>
                <td style="text-align:center" id="numTotalVulnerabilities{{ $index }}">
                    {{ scan.numberTotalVulnerabilities }}
                </td>
                <td style="text-align:center" id="numHiddenVulnerabilities{{ $index }}">
                    {{ scan.numberHiddenVulnerabilities }}
                </td>
                <c:if test="${ canUploadScans }">
                    <td>
                        <a ng-hide="scan.deleting" class="btn btn-danger" ng-click="deleteScan(scan)">Delete Scan</a>
                        <a ng-show="scan.deleting" class="btn btn-danger" ng-disabled>
                            <span class="spinner"></span>
                            Deleting
                        </a>
                    </td>
                    <td>
                        <a class="pointer" ng-click="viewScan(scan)">View Scan</a>
                    </td>
                </c:if>
            </tr>
        </tbody>
    </table>

</tab>