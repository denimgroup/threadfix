<div class="accordion-inner" ng-repeat="vulnerability in element.vulns">
    <span ng-hide="treeApplication">
        <div class="vuln-tree-label">Application</div>
        <span id="teamAndAppText{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}">{{ treeTeam ? vulnerability.team.name : "" }} / {{ vulnerability.app.name }}</span>
        <br>
    </span>

    <span ng-show="treeApplication" class="vuln-tree-checkbox">
        <input id="checkbox{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}" type="checkbox" ng-model="vulnerability.checked" ng-change="applyVulnerabilityChecked(element, vulnerability)"/>
    </span>

    <!-- Path + Parameter -->
    <div ng-if="!vulnerability.dependency">
        <div ng-if="vulnerability.path || vulnerability.parameter">
            <div class="vuln-tree-label">Path</div>
            <span id="path{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}">{{ vulnerability.path }}</span>
            <br>
            <div class="vuln-tree-label">Parameter</div>
            <span id="parameter{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}">{{ vulnerability.parameter }}</span>
            <br>
        </div>
        <div ng-if="vulnerability.calculatedFilePath">
            <div class="vuln-tree-label">File</div>
            <span id="file{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}">{{ vulnerability.calculatedFilePath }}</span>
            <br>
        </div>
    </div>

    <!-- Dependency -->
    <div ng-if="vulnerability.dependency">
        <div class="vuln-tree-label">CVE</div>
        <span id="cve{{ $index }}">
            {{ vulnerability.dependency.cve }}
            (<a target="_blank" id="linkCve{{ $index }}" href="http://cve.mitre.org/cgi-bin/cvename.cgi?name={{ vulnerability.dependency.cve }}">View</a>)
        </span>
        <br>
        <div class="vuln-tree-label">Component</div>
        <span id="cveComponent{{ $index }}">
            {{ vulnerability.dependency.componentName }}
        </span>
        <br>
        <div class="vuln-tree-label">Description</div>
        <span id="cveDescription{{ $index }}">
            {{ vulnerability.dependency.description }}
        </span>
        <br>
    </div>

    <!-- Scanner Badges -->
    <span id="channel{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}{{ name }}" ng-repeat="name in vulnerability.channelNames" class="badge">{{ name }}</span>
    <br>
    <a id="defectBadge{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}"
       ng-href="{{ vulnerability.defect.defectURL }}"
       target="_blank"
       ng-show="vulnerability.defect"
       ng-class="{
        'badge-critical': vulnerability.defect.bugImageName === 'icn_bug_red_stroke.png',
        'badge-low': vulnerability.defect.bugImageName === 'icn_bug_grn_stroke.png',
        }"
       class="badge">
        Issue {{ vulnerability.defect.nativeId }} ({{ vulnerability.defect.status }})
    </a>
    <br ng-show="vulnerability.defect">

    <!-- Comments + Documents -->
    <span id="commentsButton{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}" class="pointer" ng-click="vulnerability.showComments = !vulnerability.showComments">
        {{ vulnerability.vulnerabilityComments.length ? vulnerability.vulnerabilityComments.length : 0 }} <span class="icon icon-comment"></span>
    </span>
    <span id="documentsButton{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}" class="pointer" ng-click="vulnerability.showDocuments = !vulnerability.showDocuments">
        {{ vulnerability.documents.length ? vulnerability.documents.length : 0 }} <span class="icon icon-file"></span>
    </span>
    <span class="pointer"><a id="viewMoreLink{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}" ng-click="goTo(vulnerability)">View More</a></span>
    <br>

    <!-- Comments body -->
    <div ng-show="vulnerability.showComments" style="display:inline-block">
        <h4>Comments</h4>
        <div id="commentDiv{{ $index }}" >
            <%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>
        </div>
        <a id="addCommentButton{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}" class="btn margin-bottom" ng-click="showCommentForm(vulnerability, tags)">Add Comment</a>
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
                    <td id="docName{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}">{{ document.name }}</td>
                    <td id="type{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}" >{{ document.type }}</td>
                    <td id="uploadDate{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}" >
                        {{ document.uploadedDate | date:'medium' }}
                    </td>
                    <td class="centered">
                        <a target="_blank" id="downloadLink{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}" class="btn" type="submit" ng-href="{{ getDocumentUrl(vulnerability, document) }}">Download</a>
                    </td>
                    <td>
                        <a id="viewFile{{ category.name }}{{ element.genericVulnerability.displayId }}{{ $index }}"  ng-href="{{ getDocumentUrl(vulnerability, document) }}" target="_blank">View File</a>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
</div>