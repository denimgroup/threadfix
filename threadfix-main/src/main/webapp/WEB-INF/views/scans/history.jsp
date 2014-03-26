<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Scan History</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/scan-history-controller.js"></script>
</head>

<body id="scans">
	<h2>Scans</h2>
	
	<div id="helpText">
		This page lists all of the scans that have been uploaded to ThreadFix.
	</div>
		
	<spring:url value="" var="emptyUrl" />
	<div ng-controller="ScanHistoryController" ng-init="csrfToken = '<c:out value='${ emptyUrl }'/>'">
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
				<tr ng-hide="scans" class="bodyRow">
					<td colspan="10" style="text-align: center;">Loading Scans.</td>
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
                    <td>
                        <a id="importTime{{ $index }}" ng-click="goTo(scan)">
                            View Scan
                        </a>
                    </td>
                </tr>
			</tbody>
		</table>
	</div>
</body>