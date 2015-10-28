<div ng-controller="ScanMappedFindingTableController" ng-init="loading = true">

	<h4 style="padding-top:8px">Mapped Findings</h4>

    <div ng-form="mappedForm" class="pagination" ng-show="numFindings > 100">
        <pagination class="no-margin" total-items="numFindings / 10" max-size="5" page="page"></pagination>

        <input name="pageMappedInput"  ng-enter="goToPage(mappedForm.$valid)" style="width:50px" type="number" ng-model="pageInput" max="{{numberOfMappedPages * 1}}" min="1"/>
        <button class="btn" ng-class="{ disabled : mappedForm.$invalid }" ng-click="goToPage(mappedForm.$valid)"> Go to Page </button>
        <span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.min || mappedForm.pageMappedInput.$error.max">Input number from 1 to {{numberOfMappedPages}}</span>
        <span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.number">Not a valid number</span>
    </div>

    <div ng-show="loading" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <table class="table tf-colors" id="1">
		<thead>
			<tr>
				<th class="first">Severity</th>
				<th>Vulnerability Type</th>
				<th>Path</th>
				<th class="medium">Parameter</th>
				<th># Merged Results</th>
				<th class="short"></th>
			</tr>
		</thead>
		<tbody>

        <tr ng-hide="findingList || loading" class="bodyRow">
            <td colspan="6" style="text-align: center;"> No Findings were mapped to vulnerabilities.</td>
        </tr>

        <tr ng-repeat="finding in findingList" class="bodyRow" ng-class="{
                        error: finding.channelSeverity.numericValue === 5,
                        warning: finding.channelSeverity.numericValue === 4,
                        success: finding.channelSeverity.numericValue === 3,
                        info: finding.channelSeverity.numericValue === 2 || finding.channelSeverity.numericValue === 1
                        }">
            <td id="mappedSeverity{{ index }}">{{ finding.channelSeverity.name }}</td>
            <td>{{ finding.channelVulnerability.name }}</td>
            <td ng-hide="finding.dependency" class="long-path-word-wrap" id="mappedPath{{ index }}">{{ finding.surfaceLocation.path }}</td>
            <td ng-hide="finding.dependency" id="mappedParameter{{ index }}">
                <div class="word-wrap medium">
                    {{ finding.surfaceLocation.parameter }}
                </div>
            </td>
            <td ng-show="finding.dependency" colspan="2" class="pointer">
                {{ finding.dependency.refId }}
                (<a target="_blank" id="cve{{ index }}" href="{{ finding.dependency.refLink }}">View</a>)
            </td>
            <td>{{ finding.numberMergedResults }}</td>
            <td class="pointer">
                <a id="mappedVulnType{{ index }}" ng-click="goTo(finding)">
                    View Finding
                </a>
            </td>
        </tr>
		</tbody>
	</table>
</div>