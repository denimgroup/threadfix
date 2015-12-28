<h2>Finding Details</h2>

<div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div>

<div style="padding-bottom:10px" ng-show="initialized">
    <a class="btn" ng-show="finding.vulnerability" ng-click="goToVulnerability()">View Vulnerability</a>
    <c:if test="${ canModifyVulnerabilities }">
        <a class="btn" ng-click="goToFindingMerge()">Merge with Other Findings</a>
    </c:if>
</div>

<table class="dataTable" ng-show="initialized">
    <tbody>
        <tr ng-show="finding.urlReference">
            <td class="bold">Link</td>
            <td class="inputValue"><a id="sourceUrl" href="{{ finding.urlReference }}" target="_blank">{{ finding.urlReference }}</a></td>
        </tr>
        <tr>
            <td class="bold">Scanner Vulnerability</td>
            <td class="inputValue" id="scannerVulnerabilityType">{{ finding.channelVulnerability.name }}</td>
        </tr>
        <tr>
            <td class="bold">Scanner Confidence Rating</td>
            <td class="inputValue" id="scannerConfidenceRating">{{ finding.confidenceRating }}</td>
        </tr>
        <tr>
            <td class="bold">Scanner Severity</td>
            <td class="inputValue" id="scannerSeverity">{{ finding.channelSeverity.name }}</td>
        </tr>
        <tr>
            <td class="bold">CWE Vulnerability</td>
            <td class="inputValue" id="genericVulnerabilityName">
                        <span ng-show="finding.channelVulnerability.genericVulnerability"
                              tooltip="CWE-{{ finding.channelVulnerability.genericVulnerability.displayId }}">
                        {{ finding.channelVulnerability.genericVulnerability.name }}</span></td>
        </tr>
        <tr>
            <td class="bold">Severity</td>
            <td class="inputValue" id="genericSeverityName">{{ finding.channelSeverity.severityMap.genericSeverity.displayName }}</td>
        </tr>
        <tr ng-hide="finding.dependency">
            <td class="bold">Description</td>
            <td class="inputValue" id="longDescription" style="max-width:500px;word-wrap: break-word;">{{ finding.longDescription }}</td>
        </tr>
        <tr ng-hide="finding.dependency">
            <td class="bold">Path</td>
            <td class="inputValue" id="path">{{ finding.surfaceLocation.path }}</td>
        </tr>
        <tr ng-hide="finding.dependency">
            <td class="bold">Parameter</td>
            <td class="inputValue" id="parameter">{{ finding.surfaceLocation.parameter }}</td>
        </tr>
        <tr ng-hide="finding.dependency">
            <td class="bold">Native ID</td>
            <td class="inputValue" id="nativeId">
                <span ng-show="finding.displayId">{{ finding.displayId }}</span>
                <span ng-hide="finding.displayId">{{ finding.nativeId }}</span>
            </td>
        </tr>
        <tr ng-hide="finding.dependency">
            <td class="bold">Attack String</td>
            <td class="inputValue"><pre ng-show="finding.attackString" id="attackString">{{ finding.attackString }}</pre></td>
        </tr>
        <tr ng-hide="finding.dependency" class="odd">
            <td class="bold" valign=top>Scanner Detail</td>
            <td class="inputValue" style="word-wrap: break-word;list-style: square"><pre ng-show="finding.scannerDetail" id="scannerDetail">{{ finding.scannerDetail }}</pre></td>
        </tr>
        <tr ng-hide="finding.dependency">
            <td class="bold" valign=top>Scanner Recommendation</td>
            <td class="inputValue" style="word-wrap: break-word;list-style: square"><pre ng-show="finding.scannerRecommendation" id="scannerRecommendation">{{ finding.scannerRecommendation }}</pre></td>
        </tr>
        <tr ng-hide="finding.dependency">
            <td class="bold" valign=top>Attack Request</td>
            <td class="inputValue" style="word-wrap: break-word;"><pre ng-show="finding.attackRequest" id="attackRequest">{{ finding.attackRequest }}</pre></td>
        </tr>
        <tr ng-hide="finding.dependency">
            <td class="bold" valign=top>Attack Response</td>
            <td class="inputValue" style="word-wrap: break-word;"><pre ng-show="finding.attackResponse" id="attackResponse">{{ finding.attackResponse }}</pre></td>
        </tr>
        <tr ng-show="finding.dependency">
            <td class="bold">Reference</td>
            <td class="inputValue" id="dependency">
                {{ finding.dependency.refId }}
                (<a target="_blank" href="{{ finding.dependency.refLink }}">View</a>)
            </td>
        </tr>
        <tr ng-show="finding.dependency">
            <td class="bold" valign=top>File Name</td>
            <td class="inputValue" style="word-wrap: break-word;"><pre ng-show="finding.attackString" id="dependencyFileName">{{ finding.dependency.componentName }}</pre></td>
        </tr>
        <tr ng-show="finding.dependency">
            <td class="bold" valign=top>File Path</td>
            <td class="inputValue" style="word-wrap: break-word;"><pre ng-show="finding.dependency.componentFilePath" id="dependencyFilePath">{{ finding.dependency.componentFilePath }}</pre></td>
        </tr>
        <tr ng-show="finding.dependency">
            <td class="bold" valign=top>Description</td>
            <td class="inputValue" style="word-wrap: break-word;"><pre ng-show="finding.dependency.description" id="dependencyDesc">{{ finding.dependency.description }}</pre></td>
        </tr>
        <tr ng-show="finding.dependency && finding.scannerRecommendation">
            <td class="bold" valign=top>Scanner Recommendation</td>
            <td class="inputValue" style="word-wrap: break-word;list-style: square"><pre ng-show="finding.scannerRecommendation" id="scannerRecommendationInDependency">{{ finding.scannerRecommendation }}</pre></td>
        </tr>
        <tr>
            <td class="bold" valign=top>Raw Finding</td>
            <td class="inputValue" style="word-wrap: break-word;"><pre ng-show="finding.rawFinding" id="rawFinding">{{ finding.rawFinding }}</pre></td>
        </tr>
    </tbody>
</table>

<h3 ng-show="finding.dataFlowElements && initialized">Data Flow</h3>
<table ng-show="finding.dataFlowElements && initialized" class="dataTable">
    <tbody ng-repeat="flowElement in finding.dataFlowElements">
        <tr>
            <td class="bold">File Name</td>
            <td class="inputValue">{{ flowElement.sourceFileName }}</td>
        </tr>
        <tr>
            <td class="bold">Line Number</td>
            <td class="inputValue">{{ flowElement.lineNumber }}</td>
        </tr>
        <tr>
            <td class="bold">Line Text</td>
            <td class="inputValue"><code>{{ flowElement.lineText }}</code></td>
        </tr>
        <tr>
            <td class="bold">Column Number</td>
            <td class="inputValue">{{ flowElement.columnNumber }}</td>
        </tr>
        <tr>
            <td class="bold">Sequence</td>
            <td class="inputValue">{{ flowElement.sequence }}</td>
        </tr>
        <tr>
            <td colspan="2">============================================================</td>
        </tr>
    </tbody>
</table>