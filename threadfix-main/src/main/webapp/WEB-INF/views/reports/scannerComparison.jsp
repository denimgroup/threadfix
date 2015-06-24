<div style="overflow: auto" ng-show="reportId==Scan_Comparison_Summary_Id" id="scanComparisonDiv">

    <h2 id="scanComparisonTitle">Scan Comparison Summary</h2>

    <table class="dataTable">
        <thead>
        <tr>
            <td class="long first"><b>Summary</b></td>
            <td></td>
        </tr>
        </thead>
        <tbody>
        <tr>
            <td>Team</td>
            <td class="inputValue">{{title.teams}}</td>
        </tr>
        <tr>
            <td>Application</td>
            <td class="inputValue">{{title.apps}}</td>
        </tr>
        <tr>
            <td>Application Tag</td>
            <td class="inputValue">{{title.tags}}</td>
        </tr>
        <tr>
            <td>Vulnerability Tag</td>
            <td class="inputValue">{{title.vulnTags}}</td>
        </tr>
        <tr>
            <td>Total Vulnerabilities</td>
            <td class="inputValue">{{totalVuln}}</td>
        </tr>
        </tbody>
    </table>

    <table style="padding-bottom:100px;table-layout:fixed;" class="sortable table table-striped tablesorter" id="scanComparisonTable">
        <thead>
        <tr class="darkBackground">
            <th id="type" class="first" style="text-align: left;width:200px;word-wrap: break-word;">Scanner Name</th>
            <th id="foundCount"># Found</th>
            <th id="foundPercent">% Found</th>
            <th id="fpCount"># False Positives</th>
            <th id="fpPercent" class="last">% False Positives</th>
            <th id="foundHAMEndpoint"># Found HAM Endpoint</th>
            <th id="foundHAMEndpointPercent" class="last">% Found HAM Endpoint</th>
        </tr>
        </thead>

        <tbody>
        <tr id="scan{{ $index }}" ng-repeat = "scan in scannerComparisonData" class="bodyRow">
            <td id="scanName{{ $index }}" style="text-align: left;word-wrap: break-word;" >{{ scan.channnelName }}</td>
            <td id="foundCount{{ $index }}">{{ scan.foundCount }}</td>
            <td id="foundPercent{{ $index }}">{{ scan.foundPercent }}</td>
            <td id="fpCount{{ $index }}">{{ scan.fpCount }}</td>
            <td id="fpPercent{{ $index }}">{{ scan.fpPercent }}</td>
            <td id="foundHAMEndpoint{{ $index }}">{{ scan.HAMCount }}</td>
            <td id="foundHAMEndpointPercent{{ $index }}">{{ scan.HAMPercent }}</td>
        </tr>
        </tbody>
    </table>
</div>