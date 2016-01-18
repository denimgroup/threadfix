
<table class="table sortable table-hover" id="2">
    <thead>
    <tr>
        <th style="width:5px; padding:0"></th>
        <th style="width:10px"></th>
        <th>Scanner Name</th>
        <th>Finding Name</th>
        <th>Location</th>
        <th>Scanner Confidence Rating</th>
    </tr>
    </thead>
    <tbody>
    <tr ng-repeat-start="finding in findings" class="pointer finding-row" ng-click="toggle(finding)">
        <td class="{{ badgeClassMap[finding.channelSeverity.severityMap.genericSeverity.intValue] }}" style="padding:0"></td>
        <td><span class="caret-right" ng-class="{ expanded: finding.expanded }"></span></td>
        <td id="scannerName{{ $index }}">{{ finding.scannerName }}</td>
        <td id="vulnName{{ $index }}" style="word-wrap: break-word;">{{ finding.channelVulnerability.name }}</td>
        <td style="word-wrap: break-word;">{{ finding.surfaceLocation.humanLocation }}</td>
        <td id="confidenceRating{{ $index }}"> {{ finding.confidenceRating }} </td>
    </tr>
    <tr ng-repeat-end>
        <td style="padding:0; border-top:inherit"></td>
        <td class="grey-background" style="padding:inherit; border-top:inherit" colspan="5">
            <div style="padding:5px 10px 25px" ng-show="finding.expanded">
                <table class="dataTable finding-table">
                    <tr ng-if="finding.channelSeverity.name">
                        <td class="bold">Scanner Severity</td>
                        <td>{{ finding.channelSeverity.name }}</td>
                    </tr>
                    <tr ng-if="finding.longDescription">
                        <td class="bold">Description</td>
                        <td>{{ finding.longDescription }}</td>
                    </tr>
                    <tr ng-if="finding.surfaceLocation.path">
                        <td class="bold">Path</td>
                        <td>{{ finding.surfaceLocation.path }}</td>
                    </tr>
                    <tr ng-if="finding.surfaceLocation.parameter">
                        <td class="bold">Parameter</td>
                        <td>{{ finding.surfaceLocation.parameter }}</td>
                    </tr>
                    <tr ng-if="finding.attackString">
                        <td class="bold">Attack String</td>
                        <td><pre>{{ finding.attackString }}</pre></td>
                    </tr>
                    <tr ng-if="finding.scannerDetail">
                        <td class="bold">Scanner Detail</td>
                        <td style="word-wrap: break-word;"><pre>{{ finding.scannerDetail }}</pre></td>
                    </tr>
                    <tr ng-if="finding.scannerRecommendation">
                        <td class="bold">Scanner Recommendation</td>
                        <td><pre>{{ finding.scannerRecommendation }}</pre></td>
                    </tr>
                    <tr ng-if="finding.attackRequest">
                        <td class="bold">Attack Request</td>
                        <td><pre>{{ finding.attackRequest }}</pre></td>
                    </tr>
                    <tr ng-if="finding.attackResponse">
                        <td class="bold">Attack Response</td>
                        <td><pre>{{ finding.attackResponse }}</pre></td>
                    </tr>
                </table>
                <div style="padding:8px;">
                    <div ng-if="finding.dataFlowElements && finding.dataFlowElements.length > 0" style="font-weight:bold; margin-top:10px;">Data Flow</div>
                    <div ng-repeat="dataFlowElement in finding.dataFlowElements">
                        {{ dataFlowElement.sourceFileName }} line {{ dataFlowElement.lineNumber }}
                        <pre>{{ dataFlowElement.lineText }}</pre>
                    </div>
                    <c:if test="${ canModifyVulnerabilities }">
                        <div ng-if = "finding.scannerName === 'Manual'">
                            <a id="editLink" ng-click="openEditFindingModal(finding)" class="pointer">Edit</a>
                        </div>
                        <div ng-if = "finding.scannerName !== 'Manual'">
                            <a id="editDescriptionLink" ng-click="openEditDescriptionModal(finding, $index)" class="pointer">Edit Description</a>
                        </div>
                    </c:if>
                    <div>
                        <a id="viewLink" ng-href="{{ finding.pageUrl }}" class="pointer">View Finding page</a>
                    </div>
                </div>
            </div>
        </td>
    </tr>
    </tbody>
</table>
