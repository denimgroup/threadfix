
<table class="table table-striped">
	<thead>
		<tr>
			<th style="width:500px">Channel Vulnerability Type</th>
            <th style="width:70px">Channel Type</th>
            <th style="width:50px">Severity</th>
			<th style="width:50px">Type</th>
			<th style="width:130px"></th>
		</tr>
	</thead>
	<tbody>
        <tr ng-hide="currentChannelVulnFilters" class="bodyRow">
            <td colspan="5" class="centered">No filters found.</td>
        </tr>
        <tr ng-show="currentChannelVulnFilters" ng-repeat="vulnFilter in currentChannelVulnFilters" class="bodyRow">
            <td id="genericVulnerability{{ $index }}">
                {{ vulnFilter.sourceChannelVulnerability.name }}
            </td>
            <td>
                {{ vulnFilter.sourceChannelType.name }}
            </td>
            <td style="word-wrap: break-word;">
                <div id="genericSeverity{{ $index }}" ng-if="!vulnFilter.targetGenericSeverity">
                    Ignore
                </div>
                <div id="genericSeverity{{ $index }}" ng-if="vulnFilter.targetGenericSeverity">
                    {{ vulnFilter.targetGenericSeverity.displayName }}
                </div>
            </td>
            <td>
                {{ type }}
            </td>
            <td id="edit{{ $index }}">
                <a class="btn" ng-click="editChannelFilter(vulnFilter)">Edit/Delete</a>
            </td>
        </tr>
	</tbody>
</table>
