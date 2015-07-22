<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Channel Severity Mappings</title>
	<cbs:cachebustscript src="/scripts/channel-severity-mappings-page-controller.js"/>
</head>

<body id="channelSeverityMappings" ng-controller="ChannelSeverityMappingsPageController">
	<h2>Channel Severity Mappings</h2>

	<%@ include file="/WEB-INF/views/angular-init.jspf"%>
	<%@ include file="/WEB-INF/views/successMessage.jspf" %>
	<%@ include file="/WEB-INF/views/errorMessage.jspf"%>

	<div ng-show="loading" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

	<div style="padding-bottom:10px">
		<a ng-show="channelTypesData" class="btn" id="expandAllButton" ng-click="expand()">Expand All</a>
		<a ng-show="channelTypesData" class="btn" id="collapseAllButton" ng-click="contract()">Collapse All</a>

		<a ng-show="channelTypesData" class="btn btn-primary" id="updateButton1"  ng-class="{ disabled : !severityMapChanged }" ng-click="update()">Update</a>
	</div>

	<table ng-show="channelTypesData" class="table table-hover white-inner-table">
		<thead/>
		<tbody>
		<tr ng-repeat-start="channelType in channelTypesData" id="channelRow{{ $index }}" class="pointer"
			ng-show="channelType.channelSeverities">
			<td id="channelTypeCaret{{ $index }}" ng-click="toggle(channelType)">
				<span ng-class="{ expanded: channelType.expanded }" class="caret-right"></span>
			</td>
			<td ng-click="toggle(channelType)" id="channelTypeName{{ $index }}">
				<div style="word-wrap: break-word;width:300px;text-align:left;">{{ channelType.channelType.name }}</div>
			</td>
		</tr>
		<tr
			ng-repeat-end class="grey-background" >
			<td colspan="2">
				<div ng-show="channelType.expanded">
					<div ng-show='channelType.channelSeverities' >
						<table id="channelTypeSeveritiesTable{{ $index }}" >
							<thead>
							<tr>
								<th class="centered">Channel Severity</th>
								<th class="centered">Generic Severity</th>
							</tr>
							</thead>
							<tr class="app-row" ng-repeat="channelSeverity in channelType.channelSeverities">

								<td class="centered" id="channelSeverity{{ channelSeverity.id }}">{{ channelSeverity.name }}</td>
								<td class="centered" id="genericSeverity{{ channelSeverity.id }}">
									<select ng-model="channelSeverity.severityMap.genericSeverity.id" ng-change="change(channelSeverity)">
										<option ng-selected="channelSeverity.severityMap.genericSeverity.id === genericSeverity.id"
												ng-repeat="genericSeverity in genericSeverities"
												value="{{ genericSeverity.id }}">
											{{ genericSeverity.displayName }}
										</option>
									</select>
								</td>

							</tr>
						</table>
					</div>
				</div>
			</td>
		</tr>
		</tbody>
	</table>
</body>
