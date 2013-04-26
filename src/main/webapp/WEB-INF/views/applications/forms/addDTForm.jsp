<%@ include file="/common/taglibs.jsp"%>

<div class="modal-header">
	<h4 id="myModalLabel">Add Defect Tracker</h4>
</div>
<div id="addDTFormDiv">
<spring:url value="/organizations/{orgId}/applications/{appId}/edit/addDTAjax" var="saveUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<form:form id="addDTForm" style="margin-bottom:0px;" modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
	<div id="addDefectTrackerDivInForm" class="modal-body"
		<c:if test="${ empty defectTrackerList }">
			data-has-defect-trackers=""
		</c:if>
		<c:if test="${ not empty defectTrackerList }">
			data-has-defect-trackers="1"
		</c:if>
	>
		<table>
			<tr class="left-align">
				<td>Defect Tracker</td>
				<td class="inputValue">
					<c:if test="${ not empty defectTrackerList }">
						<select style="margin:5px;" id="defectTrackerId" name="defectTracker.id">
							<option value="0">&lt;none&gt;</option>
							<c:forEach items="${ defectTrackerList }" var="listDefectTracker">
								<c:choose>
									<c:when test="${ not empty newDefectTracker && newDefectTracker.id == listDefectTracker.id}">
										<option value="${ listDefectTracker.id }" selected="selected">
											<c:out value="${ listDefectTracker.name }"/>
										</option>
									</c:when>
									<c:when test="${ empty newDefectTracker && not empty application.defectTracker && 
											application.defectTracker.id == listDefectTracker.id}">
										<option value="${ listDefectTracker.id }" selected="selected">
											<c:out value="${ listDefectTracker.name }"/>
										</option>
									</c:when>
									<c:otherwise>
										<option value="${ listDefectTracker.id }"><c:out value="${ listDefectTracker.name }"/></option>
									</c:otherwise>
								</c:choose>
								
							</c:forEach>
						</select>
						<c:if test="${ canManageDefectTrackers }">
							<a style="padding-left:10px;" id="configureDefectTrackersLink" href="<spring:url value="/configuration/defecttrackers/new"/>">Create a Defect Tracker</a>
						</c:if>
					</c:if>
					<a id="createDefectTrackerButtonInModal" href="#" class="btn" onclick="switchDTModals()">Create New Defect Tracker</a>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="defectTracker.id" cssClass="errors" />
				</td>
			</tr>
			<tr class="left-align">
				<td>Username</td>
				<td class="inputValue">
					<form:input style="margin:5px;" id="username" path="userName" size="50" maxlength="50"/>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="userName" cssClass="errors" />
				</td>
			</tr>
			<tr class="left-align">
				<td>Password</td>
				<td class="inputValue">						
					<form:password style="margin:5px;" id="password" showPassword="true" path="password" size="50" maxlength="50" />
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="password" cssClass="errors" />
				</td>
			</tr>
			<tr class="left-align">
				<td>
					<a href="#" id="jsonLink">Test Connection</a>
				</td>
				<td>
					<div id="toReplaceDT"></div>
				</td>
			</tr>
			<tr class="left-align">
				<td id="projectname">Product Name</td>
				<td class="inputValue">
					<form:select style="margin:5px;" id="projectList" path="projectName">
						<c:if test="${ not empty application.projectName }">
							<option value="${ application.projectName }"><c:out value="${ application.projectName }"/></option>
						</c:if>
					</form:select>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="projectName" cssClass="errors" />
				</td>
			</tr>
		</table>
	</div>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitDTModal" class="modalSubmit btn btn-primary" data-success-div="appDTDiv">Add Defect Tracker</a>
	</div>
</form:form>
</div>
