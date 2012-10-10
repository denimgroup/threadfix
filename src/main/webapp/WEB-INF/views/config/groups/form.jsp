<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Group <c:out value="${ accessGroup.name }"/></title>
	
</head>

<body>

	<h2><c:if test="${ accessGroup['new'] }">New </c:if>Group</h2>
	
	<spring:url value="" var="emptyUrl"></spring:url>	
	<form:form modelAttribute="accessGroup" method="post" action="${fn:escapeXml(emptyUrl) }">
		<table class="dataTable">
			<tbody>
				<tr>
					<td class="label">Name:</td>
					<td class="inputValue">
						<form:input path="name" cssClass="focus" size="70" maxlength="255" value="${ name }" />
					</td>
					<td style="padding-left:5px">
						<form:errors path="name" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td class="label">Parent Group:</td>
					<td class="inputValue">
						<c:if test="${ empty groups }">
							No Teams found.
						</c:if>
						<c:if test="${ not empty groups }">
							<form:select id="parentGroupId" path="parentGroup.id">
								<form:option value="">No Parent Group</form:option>
								<form:options items="${ groups }" itemValue="id" itemLabel="name"/>
							</form:select>
						</c:if>
					</td>
					<td style="padding-left:5px" colspan="2" >
						<form:errors path="parentGroup.id" cssClass="errors" />
					</td>
				</tr>
				<tr>
					<td class="label">Team:</td>
					<td class="inputValue">
						<c:if test="${ empty teams }">
							No Teams found.
						</c:if>
						<c:if test="${ not empty teams }">
							<form:select id="teamId" path="team.id">
								<form:option value="">No Team (Child Groups Only)</form:option>
								<form:options items="${ teams }" itemValue="id" itemLabel="name"/>
							</form:select>
						</c:if>
					</td>
					<td style="padding-left:5px" colspan="2" >
						<form:errors path="team.id" cssClass="errors" />
					</td>
				</tr>
			</tbody>
		</table>
		<br/>
		<c:if test="${ accessGroup['new'] }">
			<input id="createGroupButton" type="submit" value="Create Group" />
		</c:if>
		<c:if test="${ not accessGroup['new'] }">
			<input id="updateGroupButton" type="submit" value="Update Group Key" />
		</c:if>
		<span style="padding-left: 10px">
			<a id="backToGroupsButton" href="<spring:url value="/configuration/groups"/>">Back to Groups</a>
		</span>
	</form:form>
</body>