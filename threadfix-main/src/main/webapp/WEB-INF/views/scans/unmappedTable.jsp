<%@ include file="/common/taglibs.jsp"%>

<div ng-form="unmappedForm" class="pagination" ng-show="numFindings > numberPerPage">
    <pagination class="no-margin" total-items="numFindings / 10" max-size="5" page="page"></pagination>

    <input name="pageUnmappedInput"  ng-enter="goToPage(unmappedForm.$valid)" style="width:50px" type="number" ng-model="pageInput" max="{{numberOfUnmappedPages * 1}}" min="1"/>
    <button class="btn" ng-class="{ disabled : unmappedForm.$invalid }" ng-click="goToPage(unmappedForm.$valid)"> Go to Page </button>
    <span class="errors" ng-show="unmappedForm.pageUnmappedInput.$dirty && unmappedForm.pageUnmappedInput.$error.min || unmappedForm.pageUnmappedInput.$error.max">Input number from 1 to {{numberOfUnmappedPages}}</span>
    <span class="errors" ng-show="unmappedForm.pageUnmappedInput.$dirty && unmappedForm.pageUnmappedInput.$error.number">Not a valid number</span>
</div>

<div ng-show="loading" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

<table class="table" id="1">
    <thead>
        <tr>
            <th class="first">Severity</th>
            <th class="first">Scanner</th>
            <th>Vulnerability Type</th>
            <th>Path</th>
            <th style="min-width:90px;">Parameter</th>
            <th class="last"># Merged Results</th>
            <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_VULN_FILTERS">
                <th>CWE</th>
            </security:authorize>
            <th style="width:80px"></th>
        </tr>
    </thead>
    <tbody>
        <tr ng-hide="findingList || loading" class="bodyRow">
            <td colspan="7" style="text-align: center;"> All Findings were mapped to vulnerabilities.</td>
        </tr>

        <tr ng-repeat="finding in findingList" class="bodyRow" ng-class="{
                        error: finding.channelSeverity.numericValue === 5,
                        warning: finding.channelSeverity.numericValue === 4,
                        success: finding.channelSeverity.numericValue === 3,
                        info: finding.channelSeverity.numericValue === 2 || finding.channelSeverity.numericValue === 1
                        }">
            <td id="unmappedSeverity{{ index }}">{{ finding.channelSeverity.name }}</td>
            <td id="scannerName">{{ finding.scannerName }}</td>
            <td>{{ finding.channelVulnerability.name }}</td>
            <td ng-hide="finding.dependency" class="long-path-word-wrap" id="unmappedPath{{ index }}">{{ finding.surfaceLocation.path }}</td>
            <td ng-hide="finding.dependency" id="unmappedParameter{{ index }}">{{ finding.surfaceLocation.parameter }}</td>
            <td ng-show="finding.dependency" colspan="2" class="pointer">
                {{ finding.dependency.refId }}
                (<a target="_blank" id="cve{{ index }}" href="{{ finding.dependency.refLink }}">View</a>)
            </td>
            <td>{{ finding.numberMergedResults }}</td>
            <security:authorize ifAnyGranted="ROLE_CAN_MANAGE_VULN_FILTERS">
                <td>
                    <a class="pointer" ng-if="!finding.genericVulnerabilityName" id="createMapping{{ index }}" ng-click="createMapping(finding)">
                        Create Mapping
                    </a>
                    <a class="pointer" ng-if="finding.genericVulnerabilityName" id="createVulnerabilities{{ index }}" ng-click="createVulnerabilities(finding)">
                        Create Vulnerabilities
                    </a>
                </td>
            </security:authorize>
            <td class="pointer">
                <a id="unmappedVulnType{{ index }}"  ng-href="{{ finding.pageUrl }}">
                    View Finding
                </a>
            </td>
        </tr>

    </tbody>
</table>