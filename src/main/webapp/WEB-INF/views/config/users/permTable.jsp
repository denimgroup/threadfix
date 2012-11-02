<%@ include file="/common/taglibs.jsp"%>

<body>

	<c:if test="${ not empty error }">
		<div class="errors"><c:out value="${ error }"/></div>
	</c:if>

	<table class="filteredTable">
		<thead>
			<tr style="background-color:#43678B;color:#FFFFFF">
				<th class="medium first">Team</th>
				<th class="medium">Application</th>
				<th class="medium">Role</th>
				<th class="medium last">Delete</th>
			</tr>
		</thead>
		<tbody>
			<c:if test="${ empty maps }">
				<tr class="bodyRow">
					<td colspan="4" style="text-align:center;">
						<a href="#myModal" role="button" data-toggle="modal">Add Permissions</a>
					</td>
				</tr>
			</c:if>
		
			<c:forEach var="map" items="${ maps }">
				<c:if test="${ map.allApps and map.active}">
					<tr class="bodyRow">
						<td><c:out value="${ map.organization.name }"/></td>
						<td>All</td>
						<td><c:out value="${ map.role.displayName }"/></td>
						<td>
							<spring:url value="/configuration/users/{userId}/access/team/{mapId}/delete" var="deleteUrl">
								<spring:param name="userId" value="${ user.id }"/>
								<spring:param name="mapId" value="${ map.id }"/>
							</spring:url>
							<input id="deleteAppMap${ status.count }" type="submit" value="Delete" onclick="javascript:submitFormAndReload('${ fn:escapeXml(deleteUrl) }');return false;"/>
						</td>
					</tr>
				</c:if>
				<c:if test="${ not map.allApps }">
					<c:forEach varStatus="status" var="appMap" items="${ map.accessControlApplicationMaps }">
						<c:if test="${ appMap.active }">
							<tr class="bodyRow">
								<td><c:out value="${ map.organization.name }"/></td>
								<td><c:out value="${ appMap.application.name }"/></td>
								<td><c:out value="${ appMap.role.displayName }"/></td>
								<td>
									<spring:url value="/configuration/users/{userId}/access/app/{mapId}/delete" var="deleteUrl">
										<spring:param name="userId" value="${ user.id }"/>
										<spring:param name="mapId" value="${ appMap.id }"/>
									</spring:url>
									<input id="deleteAppMap${ status.count }" type="submit" onclick="javascript:submitFormAndReload('${ fn:escapeXml(deleteUrl) }');return false;" value="Delete" />
								</td>
							</tr>
						</c:if>
					</c:forEach>
				</c:if>
			</c:forEach>
		</tbody>
	</table>
</body>