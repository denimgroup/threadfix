<tab id='vulnTab'
     ng-controller="VulnTableController"
     ng-init="numVulns = <c:out value="${numVulns}"/>"
     heading="{{ heading }}">

    <div ng-hide="empty || vulns || hasFilters()" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <%@ include file="actionButtons.jspf" %>

    <div ng-show="showTypeSelect" class="btn-group">
        <button type="button" class="btn" ng-model="vulnType" btn-radio="'Open'">{{ numOpen }} Open</button>
        <button ng-show="numClosed > 0" type="button" class="btn" ng-model="vulnType" btn-radio="'Closed'">{{ numClosed }} Closed</button>
        <button ng-show="numFalsePositive > 0" type="button" class="btn" ng-model="vulnType" btn-radio="'False Positive'">{{ numFalsePositive }} False Positive</button>
        <button ng-show="numHidden > 0" type="button" class="btn" ng-model="vulnType" btn-radio="'Hidden'">{{ numHidden }} Hidden</button>
    </div>

    <span ng-show="vulns && loading" style="float:right" class="spinner dark"></span>

    <%@ include file="filter.jspf" %>

    <div ng-show="empty && !filtered" class="empty-tab-drop-area">
        <div>Drag and drop a scan file here to upload.</div>
    </div>

    <div ng-show="empty && filtered" class="alert alert-danger">
        These filters found 0 results.
    </div>

    <div ng-show="vulns">
        <div ng-form="form" class="pagination" ng-show="numVulns > 100">
            <pagination class="no-margin" total-items="numVulns / 10" max-size="5" page="page"></pagination>

            <input id="pageInput" name="pageInput" ng-enter="goToPage(form.$valid)" style="width:50px" type="number" ng-model="pageInput" max="{{max * 1}}" min="1"/>
            <button id="goToPageButton" class="btn" ng-class="{ disabled : form.$invalid }" ng-click="goToPage(form.$valid)"> Go to Page </button>
            <span class="errors" ng-show="form.pageInput.$dirty && form.pageInput.$error.min || form.pageInput.$error.max">Input number from 1 to {{max}}</span>
            <span class="errors" ng-show="form.pageInput.$dirty && form.pageInput.$error.number">Not a valid number</span>
        </div>

        <table class="table sortable table-hover tf-colors" style="table-layout: fixed;" id="anyid">
            <thead>
                <tr>
                    <c:if test="${ (not hideCheckboxes) and (canModifyVulnerabilities || canSubmitDefects) }">
                        <th style="width:12px" class="first unsortable"><input type="checkbox" id="chkSelectAll" ng-model="allSelected" ng-click="toggleAll()"></th>
                    </c:if>
                    <th style="width:8px;"></th>
                    <th style="width:64px" class="pointer" ng-click="setSort('Severity')">
                        Severity<span id="severityHeaderCaret"
                                      class="caret-down"
                                      ng-class="{ expanded: sort == 1 && sortType === 'Severity'}"></span>
                    </th>
                    <th style="width:260px" class="pointer" ng-click="setSort('Type')">
                        Type<span id="vulnerabilityTypeHeaderCaret"
                                  class="caret-down"
                                  ng-class="{ expanded: sort == 1 && sortType === 'Type'}"></span>
                    </th>
                    <th style="width:220px" class="pointer" ng-click="setSort('Path')">
                        Path<span id="pathHeaderCaret"
                                  class="caret-down"
                                  ng-class="{ expanded: sort == 1 && sortType === 'Path'}"></span>
                    </th>
                    <th class="pointer" style="width:90px;" ng-click="setSort('Parameter')">
                        Parameter<span id="parameterHeaderCaret"
                                       class="caret-down"
                                       ng-class="{ expanded: sort == 1 && sortType === 'Parameter'}"></span>
                    </th>
                    <th style="width:24px;"></th>
                    <th ng-show="application.defectTracker" style="width:24px;"></th>
                    <th style="width:65px;"></th>
                </tr>
            </thead>
            <tbody>
                <tr ng-repeat-start="vulnerability in vulns" class="bodyRow pointer" ng-class="{
                        error: vulnerability.severityName === 'Critical',
                        warning: vulnerability.severityName === 'High',
                        success: vulnerability.severityName === 'Medium',
                        info: vulnerability.severityName === 'Info' || vulnerability.severityName === 'Low'
                        }">
                    <c:if test="${ (not hideCheckboxes) and (canModifyVulnerabilities || canSubmitDefects) }">
                        <td style="width:12px">
                            <input class="vulnIdCheckbox" id="vulnerabilityIds{{ $index }}" ng-click="setCheckedAll(vulnerability.checked)" type="checkbox" ng-model="vulnerability.checked">
                            <input class="vulnIdCheckboxHidden" type="hidden" value="on" name="_vulnerabilityIds">
                        </td>
                    </c:if>
                    <td ng-click="expand(vulnerability)" class="pointer">
                        <span ng-class="{ expanded: vulnerability.expanded }" id="caret{{ $index }}" class="caret-right"></span>
                    </td>
                    <td ng-click="expand(vulnerability)" class="pointer" id="severity{{ $index }}"> {{ vulnerability.severityName }} </td>
                    <td ng-click="expand(vulnerability)" class="pointer" id="type{{ $index }}">
                        {{ vulnerability.vulnerabilityName }}
                    </td>

                    <td ng-hide="vulnerability.dependency" ng-click="expand(vulnerability)" class="pointer" style="word-wrap: break-word; width:100px" id="path{{ $index }}"> {{ vulnerability.path }} </td>
                    <td ng-hide="vulnerability.dependency" ng-click="expand(vulnerability)" class="pointer" id="parameter{{ $index }}"> {{ vulnerability.parameter }} </td>

                    <td ng-show="vulnerability.dependency" class="pointer" colspan="2">
                        {{ vulnerability.dependency.cve }}
                        (<a target="_blank" id="cve{{ $index }}" ng-href="http://cve.mitre.org/cgi-bin/cvename.cgi?name={{ vulnerability.dependency.cve }}">View</a>)
                    </td>

                    <td ng-show="application.defectTracker">
                        <div ng-show="vulnerability.defect" class="tooltip-container" data-placement="left" ng-attr-title="{{ vulnerability.defect.nativeId }} ({{ vulnerability.defect.status }})" style="width:100%;text-align:right;">
                            <a id="bugLink{{ $index }}" target="_blank" ng-href="{{ vulnerability.defect.defectURL }}">
                                <img ng-src="<%=request.getContextPath()%>/images/{{ vulnerability.defect.bugImageName }}" class="transparent_png" alt="Threadfix"/>
                            </a>
                        </div>
                    </td>
                    <td ng-click="expand(vulnerability)" class="expandableTrigger">
                        <div ng-show="vulnerability.findings.length > 1" id="findingIcon{{ $index }}" class="tooltip-container" data-placement="left" title="{{ vulnerability.findings.length }} Findings" style="text-align:left;">
                            <img src="<%=request.getContextPath()%>/images/icn_fork_arrow25x25.png" class="transparent_png" alt="Threadfix" />
                        </div>
                    </td>
                    <td>
                        <a id="vulnName{{ $index }}" ng-click="goTo(vulnerability)">
                            View More
                        </a>
                    </td>
                </tr>

                <tr ng-repeat-end ng-show="vulnerability.expanded" class="bodyRow expandable" ng-class="{
                        error: vulnerability.severityName === 'Critical',
                        warning: vulnerability.severityName === 'High',
                        success: vulnerability.severityName === 'Medium',
                        info: vulnerability.severityName === 'Info' || vulnerability.severityName === 'Low'
                        }">
                    <c:set var="numColumns" value="8"/>
                    <c:if test="${ not empty application.defectTracker }">
                        <c:set var="numColumns" value="9"/>
                    </c:if>
                    <td colspan="<c:out value="${ numColumns }"/>">
                        <div id="vulnInfoDiv">
                            <div class="left-tile">
                                <h4>Scan History</h4>
                                <div class="vuln-table-box" style="width:422px;margin-bottom:20px;background-color:#FFF;padding:0px;">
                                    <table class="table" style="margin-bottom:0px;">
                                        <thead class="table">
                                            <tr class="left-align">
                                                <th class="first">Channel</th>
                                                <th>Scan Date</th>
                                                <th class="last">User</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr ng-repeat="finding in vulnerability.findings" class="left-align bodyRow">
                                                <td id="scan{{ $index }}ChannelType"> {{ finding.scannerName }} </td>
                                                <td id="scan{{ $index }}ImportTime"> {{ finding.importTime }} </td>
                                                <td id="scan{{ $index }}ChannelType{{ $index }}">
                                                    <div ng-show="finding.scanOrManualUser"> {{ finding.scanOrManualUser.name }}</div>
                                                    <div ng-hide="finding.scanOrManualUser"> No user found. Probably a remote scan.</div>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>

                            <div class="right-tile">
                                <h4>Comments</h4>
                                <div class="vuln-table-box" id="commentDiv{{ $index }}" style="width:450px;margin-bottom:10px;">
                                    <%@ include file="/WEB-INF/views/applications/vulnComments.jsp" %>
                                </div>
                                <br>
                                <a id="addCommentButton{{ $index }}" class="btn margin-bottom" ng-click="showCommentForm(vulnerability)">Add Comment</a>
                            </div>
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
    <%@ include file="actionButtons.jspf" %>
</tab>
