<%@ include file="/common/taglibs.jsp"%>

<body id="table">
	<div class="accordion" id="accordion2">
		<c:forEach var="org" items="${ organizationList }" varStatus="status">
		<div id="teamDiv${ org.id }" class="accordion-group">
			<div class="accordion-heading">
				<a class="accordion-toggle" data-toggle="collapse"
					data-parent="#accordion2" href="#collapse${ org.id }"><c:out value="${ org.name }"/></a>
			</div>
			<div id="collapse${ org.id }" class="accordion-body collapse">
				<div class="accordion-inner">
					<c:if test="${ empty org.applications }">
						No applications found.<br>
					</c:if>
					<c:if test="${ not empty org.applications }">
						<table>
						<c:forEach var="app" items="${ org.applications }">
							<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
								<spring:param name="orgId" value="${ org.id }"/>
								<spring:param name="appId" value="${ app.id }"/>
							</spring:url>
							<spring:url value="/organizations/{orgId}/applications/{appId}/scans/upload" var="uploadUrl">
								<spring:param name="orgId" value="${ org.id }"/>
								<spring:param name="appId" value="${ app.id }"/>
							</spring:url>
							<tr>
								<td style="padding:5px;"><a href="${ fn:escapeXml(appUrl) }"><c:out value="${ app.name }"/></a></td>
								<td style="padding:5px;">
									<form:form style="margin-bottom:0px;" method="post" action="${ fn:escapeXml(uploadUrl) }" enctype="multipart/form-data">
										<input id="fileInput" type="file" name="file" size="50" />
										<button class="btn" id="uploadScanButton" type="submit">Upload Scan</button>
									</form:form>
								</td>
							</tr>
							
						</c:forEach>
						</table>
					</c:if>
					<spring:url value="/organizations/{orgId}" var="orgUrl">
						<spring:param name="orgId" value="${ org.id }"/>
					</spring:url>
					<div style="margin-top:10px;margin-bottom:7px;">
						<a href="#myAppModal${ org.id }" role="button" class="btn" data-toggle="modal">Add Application</a>
						<span style="padding-left:8px;"><a href="<c:out value="${ orgUrl }"/>">View Team</a></span>
					</div>
					<div id="myAppModal${ org.id }" class="modal hide fade" tabindex="-1"
						role="dialog" aria-labelledby="myModalLabel" aria-hidden="true">
						<div id="formDiv${ org.id }">
						<div class="modal-header">
							<button type="button" class="close" data-dismiss="modal"
								aria-hidden="true">X</button>
							<h4 id="myModalLabel">New Application</h3>
						</div>
						<spring:url value="/organizations/{orgId}/modalAddApp" var="saveUrl">
							<spring:param name="orgId" value="${ org.id }"/>
						</spring:url>
							<form:form style="margin-bottom:0px;" id="myAppForm${ org.id }" modelAttribute="application" method="post" autocomplete="off" action="${fn:escapeXml(saveUrl)}">
							<div class="modal-body">
								<table>
									<tr>
										<td style="padding:5px;">Name</td> 
										<td style="padding:5px;">
											<form:input style="margin-bottom:0px;" id="nameInput" path="name" cssClass="focus" size="50" maxlength="60" />
										  	<form:errors path="name" cssClass="errors" />
										</td>
									</tr>
									<tr>
										<td style="padding:5px;">URL</td>
										<td style="padding:5px;">
											<form:input style="margin-bottom:0px;" id="urlInput" path="url" size="50" maxlength="255" />
										  	<form:errors path="url" cssClass="errors" />
									  	</td>
									</tr>
									<tr>
										<td style="padding:5px;">Team</td>
										<td style="padding:5px;"><c:out value="${ org.name }"/></td>
									</tr>
									<tr>
										<td style="padding:5px;">Criticality</td>
										<td style="padding:5px;">
											<form:select style="margin-bottom:0px;" id="criticalityId" path="applicationCriticality.id">
												<form:options items="${applicationCriticalityList}" itemValue="id" itemLabel="name"/>
											</form:select>
											<form:errors path="applicationCriticality.id" cssClass="errors" />
										</td>
									</tr>
								</table>
							</div>
							<div class="modal-footer">
								<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
								<a id="submitAppModal" class="btn btn-primary" onclick="javascript:submitAjaxModal('<c:out value="${saveUrl }"/>','#myAppForm${ org.id }', '#formDiv${ org.id }', '#teamTable', '#myAppModal${ org.id }', '#collapse${ org.id }');return false;">Add Application</a>
							</div>
						</form:form>
						</div>
					</div>
				</div>
			</div>
		</div>
		</c:forEach>
	</div>
</body>