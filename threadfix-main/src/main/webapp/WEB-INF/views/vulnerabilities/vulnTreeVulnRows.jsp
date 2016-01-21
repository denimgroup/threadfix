<div class="accordion-inner" ng-repeat="vulnerability in element.vulns">
    <span ng-hide="treeApplication">
        <div class="vuln-tree-label">Application</div>
        <span id="teamAndAppText-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
              class="break-word-header">{{ treeTeam ? "" : vulnerability.team.name }} / {{ vulnerability.app.name }}</span>
        <br>
    </span>

    <span ng-show="treeApplication || treeTeam" class="vuln-tree-checkbox">
        <input id="checkbox-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
               type="checkbox" ng-model="vulnerability.checked" ng-change="applyVulnerabilityChecked(element, vulnerability)"/>
    </span>

    <!-- Path + Parameter -->
    <div ng-if="!vulnerability.dependency" style="word-wrap:break-word;">
        <div ng-if="vulnerability.path || vulnerability.parameter">
            <div class="vuln-tree-label">Path</div>
            <span id="path-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}">{{ vulnerability.path }}</span>
            <br>
            <div class="vuln-tree-label">Parameter</div>
            <span id="parameter-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}">{{ vulnerability.parameter }}</span>
            <br>
        </div>
        <div ng-if="vulnerability.calculatedFilePath">
            <div class="vuln-tree-label">File</div>
            <span id="file-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}">{{ vulnerability.calculatedFilePath }}</span>
            <br>
        </div>
        <div ng-if="(vulnerability.path || vulnerability.parameter) && vulnerability.fullUrl">
            <div class="vuln-tree-label">Full Url</div>
            <span id="fullUrl-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}">{{ vulnerability.fullUrl }}</span>
            <br>
        </div>
    </div>

    <!-- Dependency -->
    <div ng-if="vulnerability.dependency">
        <div class="vuln-tree-label">Reference</div>
        <span id="cve-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}">
            {{ vulnerability.dependency.refId }}
            (<a target="_blank" id="linkCve{{ $index }}" href="{{ vulnerability.dependency.refLink }}">View</a>)
        </span>
        <br>
        <div class="vuln-tree-label">Component</div>
        <span id="cveComponent-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}">
            {{ vulnerability.dependency.componentName }}
        </span>
        <br>
        <div class="vuln-tree-label">Description</div>
        <span id="cveDescription-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}">
            {{ vulnerability.dependency.description }}
        </span>
        <br>
    </div>

    <!-- Scanner Badges -->
    <span id="channel-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $parent.$index }}{{ name | removeSpace }}"
          ng-repeat="name in vulnerability.channelNames" class="badge">{{ name }}</span>
    <br>
    <!-- Tag Badges -->
    <span id="tag-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $parent.$index }}{{ tag.name | removeSpace }}"
          ng-repeat="tag in vulnerability.tags" class="badge pointer" ng-class="{'badge-vulnerability-tag': true}" ng-click="goToTag(tag)">{{ tag.name }}</span>
    <br ng-show="vulnerability.tags">
    <!-- Version Badges -->
    <span id="version-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $parent.$index }}{{ version.name | removeSpace }}"
          ng-repeat="version in vulnerability.versions" class="badge" ng-class="{'badge-vulnerability-version': true}">{{ version.name }}</span>
    <br ng-show="vulnerability.versions">

    <!-- Defect Information -->
    <a id="defectBadge-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
       ng-href="{{ vulnerability.defect.defectURL }}"
       target="_blank"
       ng-show="vulnerability.defect"
       ng-class="{
        'badge-critical': vulnerability.defect.opened,
        'badge-low': !vulnerability.defect.opened,
        }"
       class="badge">
        Issue {{ vulnerability.defect.nativeId }} ({{ vulnerability.defect.status }})
    </a>
    <br ng-show="vulnerability.defect">

    <a id="grcControlBadge-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
       ng-href="{{ vulnerability.grcControl.referenceUrl }}"
       target="_blank"
       ng-show="vulnerability.grcControl"
       ng-class="{
        'badge-critical': vulnerability.grcControl.bugImageName === 'icn_bug_red_stroke.png',
        'badge-low': vulnerability.grcControl.bugImageName === 'icn_bug_grn_stroke.png',
        }"
       class="badge">
        Control {{ vulnerability.grcControl.controlId }} ({{ vulnerability.grcControl.status }})
    </a>
    <br ng-show="vulnerability.grcControl">

    <!-- Comments + Documents -->
    <span id="commentsButton-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
          class="pointer" ng-click="vulnerability.showComments = !vulnerability.showComments">
        {{ vulnerability.vulnerabilityComments.length ? vulnerability.vulnerabilityComments.length : 0 }} <span class="icon icon-comment"></span>
    </span>
    <span id="documentsButton-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
          class="pointer" ng-click="vulnerability.showDocuments = !vulnerability.showDocuments">
        {{ vulnerability.documents.length ? vulnerability.documents.length : 0 }} <span class="icon icon-file"></span>
    </span>
    <span id="attacksButton-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
          class="pointer" ng-click="vulnerability.showAttacks = !vulnerability.showAttacks">
        {{ vulnerability.staticFindings.length || vulnerability.dynamicFindings.length ? vulnerability.staticFindings.length + vulnerability.dynamicFindings.length : 0 }} <span class="icon icon-list"></span>
    </span>

    <span class="pointer"><a id="viewMoreLink-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
                             ng-href="{{ vulnerability.pageUrl }}">View More</a></span>
    <br>

    <!-- Comments body -->
    <div ng-show="vulnerability.showComments" style="display:inline-block">
        <h4>Comments</h4>
        <div id="commentDiv{{ $index }}" >
            <%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>
        </div>
        <c:if test="${ canSubmitComments }">
            <a id="addCommentButton-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
               class="btn margin-bottom"
               ng-click="showCommentForm(vulnerability, commentTags)">
                Add Comment
            </a>
        </c:if>
    </div>

    <!-- Documents body -->
    <br ng-show="vulnerability.showDocuments">
    <div ng-show="vulnerability.showDocuments">
        <h4>Files</h4>
        <table ng-show="vulnerability.showDocuments" class="table">
            <thead>
            <tr>
                <th class="first">File Name</th>
                <th>Type</th>
                <th>Upload Date</th>
                <th class="centered">Download</th>
                <th></th>
            </tr>
            </thead>
            <tbody>
            <tr ng-hide="vulnerability.documents && vulnerability.documents.length > 0">
                <td style="text-align:center" colspan="5">No Documents Found</td>
            </tr>
            <tr ng-repeat="document in vulnerability.documents" class="bodyRow">
                <td id="docName-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}" class="doc-name">{{ document.name }}</td>
                <td id="type-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}" >{{ document.type }}</td>
                <td id="uploadDate-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}" >
                    {{ document.uploadedDate | date:'medium' }}
                </td>
                <td class="centered">
                    <a target="_blank" id="downloadLink-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
                       class="btn" type="submit" ng-href="{{ getDocumentUrl(vulnerability, document) }}">Download</a>
                </td>
                <td>
                    <a id="viewFile-{{ primaryPivot.name | pivotForID }}-{{ element.secondaryPivotName | pivotForID }}-{{ $index }}"
                       ng-href="{{ getDocumentUrl(vulnerability, document) }}" target="_blank">View File</a>
                </td>
            </tr>
            </tbody>
        </table>
    </div>

    <!-- Data Flow and Request/Response body  -->
    <br ng-show="vulnerability.showAttacks">
    <div ng-show="vulnerability.showAttacks">
        <div ng-show="!vulnerability.staticFindings.length && !vulnerability.dynamicFindings.length || vulnerability.staticFindings.length+vulnerability.dynamicFindings.length===0">
            <h4>No Data Flows or Request/Response Attacks found.</h4>
        </div>

        <div ng-show="vulnerability.staticFindings.length > 1">
            <h4>Data Flow Variants</h4>
            <div ng-repeat="finding in vulnerability.staticFindings" ng-show="finding.dataFlowElements">
                <a class="pointer" ng-click="toggleFinding(finding)">Toggle
                    finding {{ finding.id }} data flow (Elements: {{ finding.dataFlowElements.length }})
                </a>
                <br />

                <div id='dataFlow{{ finding.id }}' ng-show="isShowFlow{{finding.id}}">
                    <h5>
                        Finding
                        {{ finding.id }}
                        Data Flow
                    </h5>
                    <div ng-repeat="dataFlowElement in finding.dataFlowElements">
                        <table class="dataTable">
                            <tr>
                                <td colspan="2" class="inputValue">{{ dataFlowElement.sourceFileName }} line {{ dataFlowElement.lineNumber }}</td>
                            </tr>
                            <tr>
                                <td class="inputValue"><pre>{{ dataFlowElement.lineText }}</pre></td>
                            </tr>
                            <tr>
                                <td></td>
                            </tr>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div ng-show="vulnerability.staticFindings.length === 1">
            <h4>Data Flow</h4>
            <div ng-repeat="dataFlowElement in vulnerability.staticFindings[0].dataFlowElements">
                <table class="dataTable">
                    <tr>
                        <td colspan="2" class="inputValue">{{ dataFlowElement.sourceFileName }} line {{ dataFlowElement.lineNumber }}</td>
                    </tr>
                    <tr>
                        <td class="inputValue"><pre>{{ dataFlowElement.lineText }}</pre></td>
                    </tr>
                    <tr>
                        <td></td>
                    </tr>
                </table>
            </div>
        </div>

        <%@ include file="/WEB-INF/views/vulnerabilities/vulnRequestResponseAttacks.jsp" %>
    </div>

</div>