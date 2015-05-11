<div class="vuln-search-filter-control" style="width:900px;" ng-controller="VulnSearchController">

    <%--<%@ include file="../successMessage.jspf" %>--%>

    <!-- This is the Action button -->
    <c:if test="${ canModifyVulnerabilities || canSubmitDefects || canManageGrcTools }">
        <div ng-if="treeApplication">
            <div ng-show="treeApplication && vulnTree" id="btnDiv" class="btn-group" ng-controller="BulkOperationsController">
                {{ $parent | json }}
                <button ng-hide="submitting" id="actionItems" class="btn dropdown-toggle" data-toggle="dropdown" type="button">
                    Action <span class="caret"></span>
                </button>
                <ul class="dropdown-menu">
                    <c:if test="${ canSubmitDefects }">
                        <li ng-show="$parent.treeApplication.defectTracker"><a class="pointer" id="submitDefectButton" ng-click="showSubmitDefectModal()">Create Defect</a></li>
                        <li ng-show="$parent.treeApplication.defectTracker"><a class="pointer" id="mergeDefectButton" ng-click="showMergeDefectModal()">Add to Existing Defect</a></li>
                    </c:if>
                    <c:if test="${ canManageGrcTools }">
                        <li ng-show="$parent.treeApplication.grcApplication"><a class="pointer" id="submitGrcControlButton" ng-click="showSubmitGrcControlModal()">Submit GRC Control(s)</a></li>
                    </c:if>
                    <c:if test="${ canModifyVulnerabilities }">
                        <li ng-show="parameters.showOpen"><a class="pointer" id="closeVulnsButton" ng-click="closeVulnerabilities()">Close Vulnerabilities</a></li>
                        <li ng-show="parameters.showClosed"><a class="pointer" id="openVulnsButton" ng-click="openVulnerabilities()">Open Vulnerabilities</a></li>
                        <li ng-hide="parameters.showFalsePositive"><a class="pointer" id="markFalsePositivesButton" ng-click="markFalsePositives()">Mark as False Positive</a></li>
                        <li ng-show="parameters.showFalsePositive"><a class="pointer" id="unmarkFalsePositivesButton" ng-click="unmarkFalsePositives()">Unmark as False Positive</a></li>
                        <li class="dropdown-submenu">
                            <a tabindex="-1" href="#" id="changeSeverityButton">Change Severity</a>
                            <ul class="dropdown-menu">
                                <li ng-repeat="genericSeverity in genericSeverityList" ng-click="changeSeverity(genericSeverity)"><a class="pointer">{{genericSeverity.name}}</a></li>
                            </ul>
                        </li>
                        <c:if test="${ canSubmitComments }">
                            <li><a class="pointer" id="addBatchCommentBtn" ng-click="addBatchComment(tags)">Add Batch Comment</a></li>
                        </c:if>
                    </c:if>
                </ul>

                <button id="submittingButton" ng-disabled class="btn" ng-show="submitting">
                    <span class="spinner dark"></span>
                    Submitting
                </button>
            </div>
        </div>
    </c:if>

    <div id="vulnSearchDiv" class="filter-controls">
        <%@ include file="/WEB-INF/views/reports/filter.jsp" %>
    </div>
    <%@ include file="vulnSearchTree.jsp" %>

</div>
