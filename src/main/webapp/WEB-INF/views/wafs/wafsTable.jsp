<%@ include file="/common/taglibs.jsp"%>

<table class="table auto table-striped">
	<thead>
		<tr>
			<th class="long first">Name</th>
			<th class="medium">Type</th>
			<th class="centered">Edit</th>
			<th class="centered">Delete</th>
			<th class="centered last">Rules</th>
		</tr>
	</thead>
	<tbody id="wafTableBody">
	<c:if test="${ empty wafList }">
		<tr class="bodyRow">
			<td colspan="2" style="text-align:center;">No WAFs found.</td>
		</tr>
	</c:if>
	<c:forEach var="waf" items="${ wafList }">
		<tr class="bodyRow">
			<td class="details">
				<%-- <spring:url value="/wafs/{wafId}" var="wafUrl">
					<spring:param name="wafId" value="${ waf.id }" />
				</spring:url>
				<a href="${ fn:escapeXml(wafUrl) }"> --%>
					<c:out value="${ waf.name }"/>
				<!-- </a> -->
			</td>
			<td><c:out value="${ waf.wafType.name }"/></td>
			<td class="centered">	
				<a href="#editWaf${ waf.id }" role="button" class="btn" data-toggle="modal">Edit WAF</a>
				<div id="editWaf${ waf.id }" class="modal hide fade" tabindex="-1"
						role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
					<%@ include file="/WEB-INF/views/wafs/forms/editWafForm.jsp" %>
				</div>
			</td>
			<td class="centered">	
				<a href="#deleteWaf${ waf.id }" role="button" class="btn btn-primary" data-toggle="modal">Delete</a>
			</td>
			<td class="centered">	
				<a href="#wafRules${ waf.id }" role="button" class="btn" data-toggle="modal">Rules</a>
			</td>
		</tr>
	</c:forEach>
	</tbody>
</table>
<c:if test="${ canManageWafs }">
	<a href="#createWaf" role="button" class="btn" data-toggle="modal">Add WAF</a>
	<div id="createWaf" class="modal hide fade" tabindex="-1"
			role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
		<%@ include file="/WEB-INF/views/wafs/forms/createWafForm.jsp" %>
	</div>
</c:if>