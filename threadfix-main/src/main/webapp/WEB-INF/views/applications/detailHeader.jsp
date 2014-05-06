<%@ include file="/common/taglibs.jsp"%>
<spring:url value="/organizations/{orgId}" var="orgUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
</spring:url>


<ul class="breadcrumb">
    <li><a id="applicationsIndexLink" href="<spring:url value="/organizations"/>">Applications Index</a> <span class="divider">/</span></li>
    <li><a id="teamLink" href="${ fn:escapeXml(orgUrl) }">Team: <c:out value="${ application.organization.name }"/></a> <span class="divider">/</span></li>
    <li class="active">Application: <c:out value="${ application.name }"/></li>
</ul>

<div ng-controller="ApplicationPageModalController">
    <h2 style="padding-bottom:5px;line-height:1">

    <span ng-hide="config" id="nameText" style="padding-top:5px;"><c:out value="${ application.name }"/></span>
    <span ng-show="config" id="nameText" style="padding-top:5px;">{{ config.application.name }}</span>
    <c:if test="${ not empty canManageApplications }">
        <div id="btnDiv1" class="btn-group">
            <button id="actionButton1" class="btn dropdown-toggle" data-toggle="dropdown" type="button">
                Action <span class="caret"></span>
            </button>
            <ul class="dropdown-menu">

                <c:if test="${canManageApplications }">
                    <li><a class="pointer" id="editApplicationModalButton" ng-click="showEditModal()">Edit / Delete</a></li>
                </c:if>

                <c:if test="${canManageApplications }">
                    <spring:url value="/organizations/{orgId}/applications/{appId}/filters" var="vulnFiltersUrl">
                        <spring:param name="orgId" value="${ application.organization.id }"/>
                        <spring:param name="appId" value="${ application.id }"/>
                    </spring:url>
                    <li><a id="editVulnerabilityFiltersButton" href="<c:out value="${ vulnFiltersUrl }"/>" data-toggle="modal">Edit Vulnerability Filters</a></li>
                </c:if>
                <c:if test="${!canManageApplications }">
                    <li><a id="viewApplicationModalButton">Details	</a></li>
                </c:if>
                <c:if test="${ canManageUsers && enterprise}">
                    <li><a id="userListModelButton">View Permissible Users</a></li>
                </c:if>
                <c:if test="${ canUploadScans }">
                    <li><a class="pointer" id="uploadScanModalLink" ng-click="showUploadForm(false)">Upload Scan</a></li>
                    <li><a class="pointer" id="addManualFindingModalLink" ng-click="submitFindingForm()">Add Manual Finding</a></li>
                    <li ng-show="config.application.defectTracker">
                        <a id="updateDefectsLink" ng-click="updateDefectStatus()">
                            Update Defect Status
                        </a>
                    </li>
                </c:if>
            </ul>
        </div>
    </c:if>

    </h2>
</div>
<%--<%@ include file="/WEB-INF/views/applications/forms/uploadScanForm.jsp" %>--%>
<%--<%@ include file="/WEB-INF/views/applications/modals/manualFindingModal.jsp" %>--%>
<%--<%@ include file="/WEB-INF/views/applications/modals/scanParametersModal.jsp" %>--%>

<div id="editApplicationModal" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div id="editAppFormDiv">
		<%@ include file="/WEB-INF/views/applications/forms/editApplicationForm.jsp" %>
	</div>
</div> 
<%--<div id="viewApplicationModal" class="modal hide fade" tabindex="-1"--%>
	<%--role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">--%>
	<%--<div id="viewAppFormDiv">--%>
		<%--<%@ include file="/WEB-INF/views/applications/forms/viewApplicationForm.jsp" %>--%>
	<%--</div>--%>
<%--</div>--%>
<%--<div id="usersModal" class="modal hide fade" tabindex="-1"--%>
		<%--role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">--%>
		<%--<div id="editFormDiv">--%>
			<%--<%@ include file="/WEB-INF/views/config/users/permissibleUsers.jsp" %>--%>
		<%--</div>--%>
<%--</div>--%>
<%@ include file="/WEB-INF/views/successMessage.jspf" %>

<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
