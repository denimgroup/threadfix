<%@ include file="/common/taglibs.jsp"%>

<ul class="breadcrumb">
    <li><a href="<spring:url value="/"/>">Teams</a> <span class="divider">/</span></li>
    <li><a href="${ fn:escapeXml(orgUrl) }"><c:out value="${ application.organization.name }"/></a> <span class="divider">/</span></li>
    <li class="active"><c:out value="${ application.name }"/></li>
   </ul>

<h2 style="padding-bottom:5px;"><span id="nameText"><c:out value="${ application.name }"/></span>
<c:if test="${ canManageApplications }">
		<div id="appActionDiv" class="btn-group">
			<button id="appActionButton" class="btn dropdown-toggle" type="button">Action <span class="caret"></span></button>
			<ul class="dropdown-menu">
				<li>
					<a id="editApplicationModalButton" href="#editApplicationModal" role="button" data-toggle="modal">Edit</a>
				</li>
				<li>
					<a id="deleteLink" href="${ fn:escapeXml(deleteUrl) }" onclick="return confirm('Are you sure you want to delete the application?')">
						Delete
					</a>
				</li>
				<li>
					<a id="showDetailsLink${ status.count }" href="#" data-toggle="collapse" data-target="#appInfoDiv">
						Show Details
					</a>
				</li>
			</ul>
		</div>
		<script>
		$("#appActionButton").bind({
			mouseenter : function(e) {
				$("#appActionButton").dropdown('toggle');
			},
			mouseleave : function(e) {
				$("#appActionButton").dropdown('toggle');
			}
		});
		</script>
	</c:if>
</h2>

<div id="editApplicationModal" class="modal hide fade" tabindex="-1"
	role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
	<div id="editAppFormDiv">
		<%@ include file="/WEB-INF/views/applications/forms/editApplicationForm.jsp" %>
	</div>
</div>

<%@ include file="/WEB-INF/views/successMessage.jspf" %>

<%@ include file="/WEB-INF/views/errorMessage.jsp"%>
