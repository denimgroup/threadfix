<%@ include file="/common/taglibs.jsp"%>

<body>
	<spring:url value="/edit" var="editUrl"/>
	<script>
		function showEditModal(id) {
			var options = '';
			lastId = id;
			$("#myModalLabel").html("Edit Permissions Mapping");
			$("#submitModalAdd").css("display","none");
			$("#submitModalEdit").css("display","");
			$("#myModal").modal('show');
			<c:forEach var="teamMap" items="${ maps }">
				<c:if test="${ teamMap.active }">
				if (id == <c:out value="${teamMap.id}"/>) {
					$("#orgSelect").val("<c:out value='${ teamMap.organization.id }'/>");
					$("#roleSelectTeam").val("<c:out value='${ teamMap.role.id }'/>");
					$("#orgSelect").change();
					
					if (<c:out value='${teamMap.allApps}'/> ? !$("#allAppsCheckbox").is(":checked") : $("#allAppsCheckbox").is(":checked")) {
						$("#allAppsCheckbox").click();
						toggleAppSelect();
					}
					
					<c:forEach var="appMap" items="${ teamMap.accessControlApplicationMaps }">
						<c:if test="${ appMap.active }">
							$('[name="applicationIds"][value="<c:out value='${ appMap.application.id }'/>"]').click();
							$('[name="roleIdMapList"]>option[value="<c:out value='${ appMap.application.id }'/>-<c:out value='${ appMap.role.id }'/>"]').parent().val("<c:out value='${ appMap.application.id }'/>-<c:out value='${ appMap.role.id }'/>");
						</c:if>
					</c:forEach>
				}
				</c:if>
			</c:forEach>
		}
		
		function submitEditModal() {
			completeEditUrl = '<c:out value="${editUrl}"/>'.replace("/edit",'/configuration/users/<c:out value="${user.id}"/>/access/' + lastId + "/edit");
			submitModal(completeEditUrl);
		}
		</script>

	<c:if test="${ not empty error }">
		<div class="errors"><c:out value="${ error }"/></div>
	</c:if>

	<table class="filteredTable">
		<thead>
			<tr style="background-color:#43678B;color:#FFFFFF">
				<th class="medium first">Team</th>
				<th class="medium">Application</th>
				<th class="medium">Role</th>
				<th class="short">Edit</th>
				<th class="short last">Delete</th>
				<td style="background-color:#FFFFFF;padding-left:10px"><a style="text-decoration:none;" role="button" class="btn" href="javascript:showAddModal()">Add</a></td>
			</tr>
		</thead>
		<tbody>
			<c:if test="${ empty maps }">
				<tr class="bodyRow">
					<td colspan="5" style="text-align:center;">
						<a href="javascript:showAddModal()">Add Permissions</a>
					</td>
				</tr>
			</c:if>
		
			<c:forEach var="map" items="${ maps }">
				<c:if test="${ map.allApps and map.active}">
					<tr class="bodyRow">
						<td><c:out value="${ map.organization.name }"/></td>
						<td>All</td>
						<td><c:out value="${ map.role.displayName }"/></td>
						<td style="text-align:center">
							<input id="editAppMap${ status.count }" type="submit" onclick="javascript:showEditModal(<c:out value="${ map.id }"/>)" value="Edit" />
						</td>
						<td style="text-align:center">
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
								<td style="text-align:center">
									<input id="editAppMap${ status.count }" type="submit" onclick="javascript:showEditModal(<c:out value="${ map.id }"/>)" value="Edit" />
								</td>
								<td style="text-align:center">
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