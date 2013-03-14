<%@ include file="/common/taglibs.jsp"%>

<body id="table">
	<table class="formattedTable">
		<thead>
			<tr>
				<th class="medium first">Key</th>
				<th class="short">Note</th>
				<th class="short">Edit</th>
				<th class="short">Delete</th>
				<c:if test="${ not empty apiKeyList }">
					<th class="short last">Restricted</th>
				</c:if>
			</tr>
		</thead>
		<tbody>
			<c:if test="${ empty apiKeyList }">
				<tr class="bodyRow">
					<td colspan="4" style="text-align:center;">No keys found.</td>
				</tr>
			</c:if>
			<c:forEach var="key" items="${ apiKeyList }" varStatus="status">
				<tr class="bodyRow">
					<td id="key${ status.count }">
						<c:out value="${ key.apiKey }"></c:out>
					</td>
					<td id="note${ status.count }">
						<c:out value="${ key.note }"></c:out>
					</td>
					<td style="text-align:center">
						<spring:url value="/configuration/keys/{keyId}/edit" var="keyEditUrl">
							<spring:param name="keyId" value="${ key.id }" />
						</spring:url>
						<a id="editKey${ key.id }" href="#editKeyModal${ key.id }" role="button" class="btn" data-toggle="modal">Edit</a> 
						<div id="editKeyModal${ key.id }" class="modal hide fade" tabindex="-1"
							role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
							<div id="formDiv${ key.id }">
							<div class="modal-header">
								<button type="button" class="close" data-dismiss="modal"
									aria-hidden="true">X</button>
								<h4 id="myModalLabel">Edit Key</h4>
							</div>
							<spring:url value="/configuration/keys/{keyId}/edit" var="saveUrl">
								<spring:param name="keyId" value="${ key.id }"/>
							</spring:url>
							<form:form style="margin-bottom:0px;" id="editKeyForm${ key.id }" modelAttribute="apiKey" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
								<div class="modal-body">
									<table id="noBorders" class="dataTable">
										<tbody>
											<tr>
												<td style="padding-left:8px;">Note (optional)</td>
												<td class="inputValue">
													<form:input style="margin-bottom:0px;" path="note" cssClass="focus" size="70" maxlength="255" value="${ key.note }" />
												</td>
												<td style="padding-left:5px">
													<form:errors path="note" cssClass="errors" />
												</td>
											</tr>
											<tr>
												<td style="padding-left:8px;">Restricted?</td>
												<td class="inputValue">
													<form:checkbox style="margin-bottom:0px;" path="isRestrictedKey"/>
												</td>
												<td style="padding-left:5px">
													<form:errors path="isRestrictedKey" cssClass="errors" />
												</td>
											</tr>
										</tbody>
									</table>
								</div>
								<div class="modal-footer">
									<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
									<a id="submitTeamModal" class="btn btn-primary" onclick="javascript:submitAjaxModal('${fn:escapeXml(saveUrl)}', '#editKeyForm${ key.id }', '#formDiv${ key.id }', '#tableDiv', '#editKeyModal${ key.id }');return false;">Update Key</a>
								</div>
							</form:form>
							</div>
						</div>
					</td>
					<td style="text-align:center">
						<spring:url value="/configuration/keys/{keyId}/delete" var="keyDeleteUrl">
							<spring:param name="keyId" value="${ key.id }" />
						</spring:url>
						<form:form style="margin-bottom:0px" method="POST" action="${ fn:escapeXml(keyDeleteUrl) }">
							<a id="deleteButton" class="btn btn-primary" type="submit" onclick="return confirm('Are you sure you want to delete this API Key?')">Delete</a>
						</form:form>
					</td>
					<td id="restricted${ status.count }">
						<c:out value="${ key.isRestrictedKey }"/>
					</td>
				</tr>
			</c:forEach>
			<tr class="footer">
				<td colspan="4" class="first">
					<a href="#newKeyModalDiv" role="button" class="btn" data-toggle="modal">Create New Key</a>
				</td>
				<td colspan="3" class="last pagination" style="text-align:right"></td>
			</tr>
		</tbody>
	</table>
</body>