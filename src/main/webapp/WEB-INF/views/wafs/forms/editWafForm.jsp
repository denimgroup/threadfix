<%@ include file="/common/taglibs.jsp"%>
	
<div class="modal-header">
	<button type="button" class="close" data-dismiss="modal"
		aria-hidden="true">X</button>
	<h4 id="myModalLabel">Edit WAF <c:out value="${ waf.name }"/></h4>
</div>
<spring:url value="/wafs/{wafId}/edit/ajax" var="updateUrl">
	<spring:param name="wafId" value="${ waf.id }"/>
</spring:url>
<form:form id="wafForm${ waf.id }" style="margin-bottom:0px;" modelAttribute="waf" method="post" action="${ fn:escapeXml(updateUrl) }">
	<div class="modal-body">
		<table>
			<tbody>
			    <tr>
					<td>Name</td>
					<td class="inputValue">
						<form:input style="margin:5px;" id="nameInput" path="name" cssClass="focus" size="50" maxlength="50" value="${ waf.name }"/>
					</td>
					<td style="padding-left: 5px">
						<form:errors path="name" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td>Type</td>
					<td class="inputValue">
						<form:select style="margin:5px;" id="typeSelect" path="wafType.id">
							<c:forEach var="type" items="${ wafTypeList }">
								<option value="${ type.id }"
								<c:if test="${ type.name == waf.wafType.name }">
									selected=selected
								</c:if>
								><c:out value="${ type.name }"/></option>
							</c:forEach>
						</form:select>
					</td>
					<td style="padding-left: 5px">
						<form:errors path="wafType.id" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:updateWafAndRefresh('<c:out value="${updateUrl }"/>', '#wafForm${waf.id }', '#editWaf${ waf.id }');return false;">Update WAF</a>
	</div>
</form:form>
