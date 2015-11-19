<div style="overflow: auto" ng-show="reportId==Portfolio_Report_Id">
	<div id="portfolioDiv">
		<h2>Portfolio Report</h2>

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
				<td class="inputValue break-word-header">{{title.teams}}</td>
			</tr>
			<tr>
				<td>Application</td>
				<td class="inputValue break-word-header">{{title.apps}}</td>
			</tr>
			<tr>
				<td>Application Tag</td>
				<td class="inputValue break-word-header">{{title.tags}}</td>
			</tr>
			<tr>
				<td>Number of Applications</td>
				<td class="inputValue">{{filterPortfolioApps.length}}</td>
			</tr>
			<tr>
				<td>Number of Scans</td>
				<td class="inputValue">{{noOfScans}}</td>
			</tr>
			</tbody>
		</table>

		<h3>Application Breakdown by Latest Scan</h3>

		<table class="table table-striped">
			<thead>
			<tr>
				<th style="width: 60px;" class="short first"></th>
				<th class="short">1 Month</th>
				<th class="short">3 Months</th>
				<th class="short">6 Months</th>
				<th class="short">12 Months</th>
				<th class="short">12+ Months</th>
				<th style="width: 50px;" >Never</th>
				<th style="width: 50px;" class="short last" >Total</th>
			</tr>
			</thead>
			<tbody>

			<tr ng-repeat = "app in appsByCriticality" id="{{app.criticality}}">
				<td id="{{app.criticality}}Criticality"> {{app.criticality}} </td>
				<td id="{{app.criticality}}1M"> {{app.1Month ? app.1Month : '0'}} </td>
				<td id="{{app.criticality}}3M"> {{app.3Months ? app.3Months : '0'}} </td>
				<td id="{{app.criticality}}6M"> {{app.6Months ? app.6Months : '0'}} </td>
				<td id="{{app.criticality}}12M"> {{app.12Months ? app.12Months : '0'}} </td>
				<td ng-if="app.Years" id="{{app.criticality}}Years" style="background:orange;font-weight:bold;"> {{app.Years ? app.Years : '0'}} </td>
				<td ng-if="!app.Years" id="{{app.criticality}}Years"> {{app.Years ? app.Years : '0'}} </td>
				<td ng-if="app.Never" id="{{app.criticality}}Never" style="background:red;font-weight:bold;"> {{app.Never ? app.Never : '0'}} </td>
				<td ng-if="!app.Never" id="{{app.criticality}}Never"> {{app.Never ? app.Never : '0'}} </td>
				<td id="{{app.criticality}}Total" style="background-color: #E2E4FF; font-weight: bold;"> {{app.Total ? app.Total : '0'}} </td>
			</tr>
			</tbody>
		</table>
	</div>

	<div id="portfolioScanStat">
		<h3>Portfolio Scan Statistics</h3>

		<table class="table table-striped">
			<thead>
			<tr>
				<th class="first" colspan="6"></th>
				<th class="medium">Criticality</th>
				<th class="short"># Scans</th>
				<th class="medium last">Most Recent Scan</th>
			</tr>
			</thead>
			<tbody>
			<tr ng-repeat = "row in scanStatistics">
				<td id="{{row.name}}" colspan="6" class="break-word-header">{{row.name}}</td>
				<td id="{{row.name}}{{row.criticality}}">{{row.criticality}}</td>
				<td id="{{row.name}}{{row.noOfScans}}">{{row.noOfScans}}</td>
				<td ng-if="(row.daysScanedOld !== undefined) && (row.daysScanedOld > 365)" id="{{row.name}}{{row.daysScanedOld}}" style="background:orange;font-weight:bold;">{{row.daysScanedOld}}  days ago</td>
				<td ng-if="(row.daysScanedOld !== undefined) && !(row.daysScanedOld && row.daysScanedOld > 365)" id="{{row.name}}{{row.daysScanedOld}}" >{{row.daysScanedOld}}  days ago</td>
				<td ng-if="(row.daysScanedOld === undefined)" id="{{row.name}}daysScanedOld"></td>
			</tr>
			</tbody>
		</table>
	</div>
</div>