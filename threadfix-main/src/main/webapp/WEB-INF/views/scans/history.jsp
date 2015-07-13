<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scan History</title>
    <cbs:cachebustscript src="/scripts/scan-history-controller.js"/>
</head>

<body id="scans">
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>

	<h2>Scans</h2>
	
	<div id="helpText">
		This page lists all of the scans that have been uploaded to ThreadFix.
	</div>
		
	<div ng-controller="ScanHistoryController" ng-init="loading = true">
        <!-- TODO re-add pagination -->
		<table class="table">
			<thead>
				<tr>
					<th style="width: 120px" class="long">Scan Date</th>
					<th style="text-align: left">Application</th>
					<th style="text-align: left" class="first">Team</th>
					<th>Scanner</th>
					<th>Total Vulns</th>
					<th>Hidden</th>
					<th>Critical</th>
					<th>High</th>
					<th>Medium</th>
					<th>Low</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				<tr ng-show="loading" class="bodyRow">
					<td colspan="10" style="text-align: center;">Loading Scans.</td>
				</tr>
                <tr ng-hide="loading || scans" class="bodyRow">
                    <td colspan="10" style="text-align: center;">No Scans found.</td>
                </tr>
                <tr ng-show="scans" ng-repeat="scan in scans">
                    <td>{{ scan.importTime | date:'medium' }}</td>
                    <td>{{ scan.app.name }}</td>
                    <td>{{ scan.team.name }}</td>
                    <td>{{ scan.scannerName }}</td>
                    <td>{{ scan.numberTotalVulnerabilities }}</td>
                    <td>{{ scan.numberHiddenVulnerabilities }}</td>
                    <td>{{ scan.numberCriticalVulnerabilities }}</td>
                    <td>{{ scan.numberHighVulnerabilities }}</td>
                    <td>{{ scan.numberMediumVulnerabilities }}</td>
                    <td>{{ scan.numberLowVulnerabilities }}</td>
                    <td class="pointer">
                        <a id="importTime{{ $index }}" ng-href="{{ getScanUrl(scan) }}">
                            View Scan
                        </a>
                    </td>
                </tr>
			</tbody>
		</table>
	</div>
</body>