<div class="vuln-tree">
    <h3>
        <span style="float:left">
            Results
        </span>
        <span class="spinner-div">
            <span ng-show="loadingTree" class="spinner dark"></span>
        </span>
    </h3>

    <div ng-hide="!vulnTree || vulnTree.length > 0">
        No results found.
    </div>

    <table ng-show="vulnTree">
        <tbody ng-repeat="category in vulnTree" ng-show="category.total > 0">
            <tr>
                <td>
                    <span ng-hide="category.expanded" ng-click="category.expanded = true" class="icon icon-plus-sign"></span>
                    <span ng-show="category.expanded" ng-click="category.expanded = false" class="icon icon-minus-sign"></span>
                </td>
                <td style="width:50px">
                    {{ category.name }}
                </td>
                <td ng-style="badgeWidth">
                    <span ng-style="badgeWidth" class="badge" ng-class="{
                                            'badge-important': category.intValue === 5,
                                            'badge-warning': category.intValue === 4,
                                            'badge-success': category.intValue === 3,
                                            'badge-info': category.intValue === 2 || element.intValue === 1
                                            }">
                        {{ category.total }}
                    </span>
                </td>
            </tr>
            <tr ng-repeat-start="element in category.entries" ng-show="category.expanded">
                <td></td>
                <td>
                    <span ng-hide="element.expanded" ng-click="expandAndRetrieveTable(element)" class="icon icon-plus-sign"></span>
                    <span ng-show="element.expanded" ng-click="element.expanded = false" class="icon icon-minus-sign"></span>
                </td>
                <td>
                    <span ng-style="badgeWidth" class="badge" ng-class="{
                                    'badge-important': element.intValue === 5,
                                    'badge-warning': element.intValue === 4,
                                    'badge-success': element.intValue === 3,
                                    'badge-info': element.intValue === 2 || element.intValue === 1
                                    }">
                        {{ element.numResults }}
                    </span>
                </td>
                <td>
                    {{ element.genericVulnerability.name | shortCweNames }}
                </td>
            </tr>
            <tr ng-show="category.expanded && element.expanded" ng-repeat-end>
                <td></td>
                <td colspan="4" class="vuln-tree-vuln-list">
                    <div class="accordion-group">
                        <div class="accordion-header" style="height:40px;padding: 8px 1px 4px 10px;" ng-show="element.totalVulns > 10">
                            <span>
                                <ul style="width:190px; float:left" class="nav nav-pills">
                                    <li ng-class="{ active: element.numberToShow === 10 }"> <a ng-click="updateElementTable(element, 10, 1)">10</a></li>
                                    <li ng-class="{ active: element.numberToShow === 25 }"> <a ng-click="updateElementTable(element, 25, 1)">25</a></li>
                                    <li ng-class="{ active: element.numberToShow === 50 }"> <a ng-click="updateElementTable(element, 50, 1)">50</a></li>
                                    <li ng-class="{ active: element.numberToShow === 100 }"><a ng-click="updateElementTable(element, 100, 1)">100</a></li>
                                </ul>
                            </span>
                            <span style="margin:2px;float:left;" ng-form="form" class="pagination" ng-show="element.totalVulns > element.numberToShow">
                                <pagination class="no-margin"
                                            total-items="element.totalVulns / element.numberToShow * 10"
                                            max-size="5"
                                            ng-model="element.page"
                                            page="element.page"
                                            direction-links="false"
                                            boundary-links="true"
                                            ng-click="updateElementTable(element, element.numberToShow, element.page)"></pagination>
                            </span>
                        </div>
                        <div class="accordion-inner" ng-repeat="vulnerability in element.vulns">
                            <div class="vuln-tree-label">Application</div>{{ vulnerability.team.name }} / {{ vulnerability.app.name }}
                            <br>
                            <div class="vuln-tree-label">Path</div>{{ vulnerability.path }}
                            <br>
                            <div class="vuln-tree-label">Parameter</div>{{ vulnerability.parameter }}
                            <br>
                            <span ng-repeat="name in vulnerability.channelNames" class="badge">{{ name }}</span>
                            <br>
                            <a ng-href="{{ vulnerability.defect.defectURL }}"
                               target="_blank"
                               ng-show="vulnerability.defect"
                               ng-class="{ 'badge-important': vulnerability.defect.bugImageName === 'icn_bug_red_stroke.png' }"
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
                                <c:if test="${ canModifyVulnerabilities }">
                                    <a id="uploadDocVulnModalLink" class="btn" ng-click="showUploadForm()">Add File</a>
                                </c:if>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
        </tbody>
    </table>
</div>
