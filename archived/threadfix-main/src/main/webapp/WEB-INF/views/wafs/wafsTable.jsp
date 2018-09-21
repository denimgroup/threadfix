<%@ include file="/common/taglibs.jsp"%>

<%@ include file="/WEB-INF/views/successMessage.jspf" %>

<c:if test="${ canManageWafs }">
	<a id="addWafModalButton" href="#createWaf" role="button" class="btn" data-toggle="modal">Add WAF</a>
</c:if>

<table class="table table-striped">
	<thead>
		<tr>
			<th class="long first">Name</th>
			<th class="medium">Type</th>
			<th class="centered">Edit / Delete</th>
			<th class="centered last">Rules</th>
		</tr>
	</thead>
	<tbody id="wafTableBody">
	<c:if test="${ empty wafList }">
		<tr class="bodyRow">
			<td colspan="5" style="text-align:center;">No WAFs found.</td>
		</tr>
	</c:if>
	<c:forEach var="waf" items="${ wafList }" varStatus="status">
		<tr class="bodyRow">
			<td class="details" id="wafName${ status.count }" ng-non-bindable>
				<c:out value="${ waf.name }"/>
			</td>
			<td id="wafType${ status.count }" ng-non-bindable><c:out value="${ waf.wafType.name }"/></td>
			<td class="centered">	
				<a id="editWafModalButton${ status.count }" href="#editWaf${ waf.id }" role="button" class="btn" data-toggle="modal">Edit / Delete</a>
				<div id="editWaf${ waf.id }" class="modal hide fade" tabindex="-1"
						role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
					<%@ include file="/WEB-INF/views/wafs/forms/editWafForm.jsp" %>
				</div>
			</td>
			<td class="centered">
				<spring:url value="/wafs/{wafId}" var="wafUrl">
					<spring:param name="wafId" value="${ waf.id }" />
				</spring:url>
				<a id="rulesButton${ status.count }" href="${ fn:escapeXml(wafUrl) }" role="button" class="btn">Rules</a>
			</td>
		</tr>
	</c:forEach>
	</tbody>
</table>
<c:if test="${ canManageWafs }">
	<div id="createWaf" class="modal hide fade" tabindex="-1"
			role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<%@ include file="/WEB-INF/views/wafs/forms/createWafForm.jsp" %>
	</div>
</c:if>
