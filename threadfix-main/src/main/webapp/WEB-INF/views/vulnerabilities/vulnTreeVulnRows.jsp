<div class="accordion-inner" ng-repeat="vulnerability in element.vulns">
    <span ng-hide="treeApplication">
        <div class="vuln-tree-label">Application</div>{{ treeTeam ? vulnerability.team.name : "" }} / {{ vulnerability.app.name }}
        <br>
    </span>

    <span ng-show="treeApplication" class="vuln-tree-checkbox">
        <input type="checkbox" ng-model="vulnerability.checked" ng-change="applyVulnerabilityChecked(element, vulnerability)"/>
    </span>

    <div class="vuln-tree-label">Path</div>{{ vulnerability.path }}
    <br>
    <div class="vuln-tree-label">Parameter</div>{{ vulnerability.parameter }}
    <br>
    <span ng-repeat="name in vulnerability.channelNames" class="badge">{{ name }}</span>
    <br>
    <a ng-href="{{ vulnerability.defect.defectURL }}"
       target="_blank"
       ng-show="vulnerability.defect"
       ng-class="{
        'badge-important': vulnerability.defect.bugImageName === 'icn_bug_red_stroke.png',
        'badge-success': vulnerability.defect.bugImageName === 'icn_bug_grn_stroke.png',
        }"
       class="badge">
        Issue {{ vulnerability.defect.nativeId }} ({{ vulnerability.defect.status }})
    </a>
    <br ng-show="vulnerability.defect">
    <span class="pointer" ng-click="vulnerability.showComments = !vulnerability.showComments">
        {{ vulnerability.vulnerabilityComments.length ? vulnerability.vulnerabilityComments.length : 0 }} <span class="icon icon-comment"></span>
    </span>
    <span class="pointer" ng-click="vulnerability.showDocuments = !vulnerability.showDocuments">
        {{ vulnerability.documents.length ? vulnerability.documents.length : 0 }} <span class="icon icon-file"></span>
    </span>
    <span class="pointer"><a ng-click="goTo(vulnerability)">View More</a></span>
    <br>
    <div ng-show="vulnerability.showComments" style="display:inline-block">
        <h4>Comments</h4>
        <div id="commentDiv{{ $index }}" >
            <%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>
        </div>
        <a id="addCommentButton{{ $index }}" class="btn margin-bottom" ng-click="showCommentForm(vulnerability)">Add Comment</a>
    </div>
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
                    <td id="docName{{ $index }}">{{ document.name }}</td>
                    <td id="type{{ $index }}" >{{ document.type }}</td>
                    <td id="uploadDate{{ $index }}" >
                        {{ document.uploadedDate | date:'medium' }}
                    </td>
                    <td class="centered">
                        <a target="_blank" class="btn" type="submit" ng-href="{{ getDocumentUrl(vulnerability, document) }}">Download</a>
                    </td>
                    <td>
                        <a ng-href="{{ getDocumentUrl(vulnerability, document) }}" target="_blank">View File</a>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
</div>