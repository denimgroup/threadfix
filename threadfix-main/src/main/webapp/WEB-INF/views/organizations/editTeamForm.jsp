<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">
		<span style="max-width:400px; display:inline-block" class="ellipsis">Edit Team 
			<c:if test="${ empty organization.name }">
				<c:out value="${ originalName }"/>
			</c:if>
			<c:if test="${ not empty organization.name }">
				<c:out value="${ organization.name }"/>
			</c:if>
		</span>
		<span class="delete-span">
			<spring:url value="{orgId}/delete" var="deleteUrl">
				<spring:param name="orgId" value="${ organization.id }"/>
			</spring:url>
			<a id="deleteLink" class="btn btn-danger header-button" href="${ fn:escapeXml(deleteUrl) }" 
					onclick="return confirm('Are you sure you want to delete this Team?')">Delete Team</a>
		</span>
	</h4>
</div>
<spring:url value="/organizations/{orgId}/modalEdit" var="saveUrl">
	<spring:param name="orgId" value="${ organization.id }"/>
</spring:url>
<form:form style="margin-bottom:0px;" id="organizationForm" modelAttribute="organization" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
	<div class="modal-body">
		Name <form:input style="margin-bottom:0px;margin-left:5px;" id="teamNameInput" path="name" cssClass="focus clear-after-submit" size="50" maxlength="60" />
			<form:errors path="name" cssClass="errors" />
	</div>
	<div class="modal-footer">
		<button id="closeTeamModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitTeamModal" class="modalSubmit btn btn-primary" data-success-div="teamTable">Save Edit</a>
	</div>
</form:form>