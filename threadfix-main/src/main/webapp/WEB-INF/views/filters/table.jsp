
<table class="table table-striped">
	<thead>
		<tr>
			<th style="width:500px">Vulnerability Type (CWE)</th>
			<th style="width:50px">Severity</th>
			<th style="width:50px">Type</th>
			<th style="width:130px"></th>
		</tr>
	</thead>
	<tbody>
        <tr ng-hide="currentVulnFilters" class="bodyRow">
            <td colspan="4" class="centered">No mappings found.</td>
        </tr>
        <tr ng-show="currentVulnFilters" ng-repeat="vulnFilter in currentVulnFilters" class="bodyRow">
            <td id="genericVulnerability{{ $index }}">
                <span tooltip="CWE-{{ vulnFilter.sourceGenericVulnerability.displayId }}">{{ vulnFilter.sourceGenericVulnerability.name }}</span>
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
                <a class="btn" ng-click="editFilter(vulnFilter)">Edit/Delete</a>
            </td>
        </tr>
	</tbody>
</table>
