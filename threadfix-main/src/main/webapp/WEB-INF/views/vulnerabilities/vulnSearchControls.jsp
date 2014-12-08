<div class="vuln-search-filter-control" style="width:900px;" ng-controller="VulnSearchController">

    <%--<%@ include file="../successMessage.jspf" %>--%>

    <!-- This is the Action button -->
    <c:if test="${ canModifyVulnerabilities || canSubmitDefects }">
        <div ng-if="treeApplication">
            <div ng-show="treeApplication && vulnTree" id="btnDiv" class="btn-group" ng-controller="BulkOperationsController">
                {{ $parent | json }}
                <button ng-hide="submitting" id="actionItems" class="btn dropdown-toggle" data-toggle="dropdown" type="button">
                    Action <span class="caret"></span>
                </button>
                <ul class="dropdown-menu">
                    <c:if test="${ canSubmitDefects }">
                        <li ng-show="$parent.treeApplication.defectTracker"><a class="pointer" id="submitDefectButton" ng-click="showSubmitDefectModal()">Submit Defect</a></li>
                        <li ng-show="$parent.treeApplication.defectTracker"><a class="pointer" id="mergeDefectButton" ng-click="showMergeDefectModal()">Merge Defect</a></li>
                    </c:if>
                    <c:if test="${ canModifyVulnerabilities }">
                        <li ng-show="parameters.showOpen"><a class="pointer" id="closeVulnsButton" ng-click="closeVulnerabilities()">Close Vulnerabilities</a></li>
                        <li ng-show="parameters.showClosed"><a class="pointer" id="openVulnsButton" ng-click="openVulnerabilities()">Open Vulnerabilities</a></li>
                        <li ng-hide="parameters.showFalsePositive"><a class="pointer" id="markFalsePositivesButton" ng-click="markFalsePositives()">Mark as False Positive</a></li>
                        <li ng-show="parameters.showFalsePositive"><a class="pointer" id="unmarkFalsePositivesButton" ng-click="unmarkFalsePositives()">Unmark as False Positive</a></li>
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
