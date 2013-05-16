<%@ include file="/common/taglibs.jsp"%>

	<div class="modal-header">
		<h4><c:if test="${ finding['new'] }">New</c:if> Finding</h4>
	</div>
<spring:url value="/organizations/{orgId}/applications/{appId}/scans/new" var="submitUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>	
<form:form id="manualFindingForm" style="margin-bottom:0px;" modelAttribute="finding" method="post" autocomplete="off" action="${ fn:escapeXml(submitUrl) }">
	<div class="modal-body">
	<table>
		<tbody>
			<tr>
				<c:if test="${ not isStatic }">
					<td style="padding:5px;">
						<input id="dynamicRadioButton" type="radio" name="group" value="dynamic" checked>Dynamic
					</td>
					<td style="padding:5px;">
						<input id="staticRadioButton" type="radio" name="group" value="static">Static
					</td>
				</c:if>
				<c:if test="${ isStatic }">
					<td style="padding:5px;">
						<input id="dynamicRadioButton" type="radio" name="group" value="dynamic">Dynamic
					</td>
					<td style="padding:5px;">
						<input id="staticRadioButton" type="radio" name="group" value="static" checked>Static
					</td>
				</c:if>
			</tr>
			<tr>
				<td style="padding:5px;">CWE</td>
				<td style="padding:5px;" class="inputValue">
					<spring:url value="/organizations/{orgId}/applications/{appId}/scans/new/ajax_cwe" var="ajaxCweUrl">
						<spring:param name="orgId" value="${ application.organization.id }" />
						<spring:param name="appId" value="${ application.id }" />
					</spring:url>
					<input type="hidden" id="url1" value="${ fn:escapeXml(ajaxCweUrl)}"/>
					<form:input style="width:350px;" path="channelVulnerability.code" id="txtSearch" name="txtSearch" alt="Search Criteria" 
							onkeyup="searchCweSuggest(event);" autocomplete="off"  
							onKeyPress = "return disableEnterKey(event);"
							size="50" maxlength="255"/>
					<div id="search_cwe_suggest" class="search_suggest" style="visibility: hidden"></div>
				</td>
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="channelVulnerability.code" cssClass="errors" />
				</td>
			</tr>
			<c:if test="${ not empty staticChannelVulnerabilityList }">
				<tr class="static">
					<td style="padding:5px;" valign="top">Recently Found</td>
					<td style="padding:5px;" class="inputValue">
						<select style="width:350px;" size="5" onclick="$('#txtSearch').val(this.options[this.selectedIndex].value);" id="cv_static_select">
							<c:forEach var="cv" items="${ staticChannelVulnerabilityList }">
								<option value="${ cv }">
									<c:out value="${ cv }"></c:out>
								</option>
							</c:forEach>
						</select>
					</td>
				</tr>
			</c:if>
			<c:if test="${ not empty dynamicChannelVulnerabilityList }">
				<tr class="dynamic">
					<td style="padding:5px;" valign="top">Recently Found</td>
					<td style="padding:5px;" class="inputValue">
						<select style="width:350px;" onclick="$('#txtSearch').val(this.options[this.selectedIndex].value);" size="5" id="cv_dynamic_select">
							<c:forEach var="cv" items="${ dynamicChannelVulnerabilityList }">
								<option value="${ cv }">
									<c:out value="${ cv }"></c:out>
								</option>
							</c:forEach>
						</select>
					</td>
				</tr>
			</c:if>
			<tr class="dynamic">
				<td style="padding:5px;">URL</td>
				<td style="padding:5px;" class="inputValue">
					<spring:url value="/organizations/{orgId}/applications/{appId}/scans/new/ajax_url" var="ajaxUrl">
						<spring:param name="orgId" value="${ application.organization.id }" />
						<spring:param name="appId" value="${ application.id }" />
					</spring:url>
					<input type="hidden" id="url2" value="${ fn:escapeXml(ajaxUrl)}"/>
					<form:input style="width:350px;" path="surfaceLocation.path" id="urlDynamicSearch" name="urlDynamicSearch" alt="Search Criteria" 
							onkeyup="searchUrlDynamicSuggest(event);" autocomplete="off"  
							onKeyPress = "return disableEnterKey(event);"
							size="50" maxlength="255"/>
					<div id="search_url_dynamic_suggest" class="search_suggest" style="visibility: hidden"></div>
				</td>
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="surfaceLocation.path" cssClass="errors" />
				</td>
			</tr>
			<tr class="static">
				<td style="padding:5px;">Source File</td>
				<td style="padding:5px;" class="inputValue">
					<spring:url value="/organizations/{orgId}/applications/{appId}/scans/new/ajax_url" var="ajaxUrl">
						<spring:param name="orgId" value="${ application.organization.id }" />
						<spring:param name="appId" value="${ application.id }" />
					</spring:url>
					<input type="hidden" id="url2" value="${ fn:escapeXml(ajaxUrl)}"/>
					<form:input style="width:350px;" path="dataFlowElements[0].sourceFileName" id="urlStaticSearch" name="urlSearch" alt="Search Criteria" 
							onkeyup="searchUrlStaticSuggest(event);" autocomplete="off"  
							onKeyPress = "return disableEnterKey(event);"
							size="50" maxlength="255"/>
					<div id="search_url_static_suggest" class="search_suggest" style="visibility: hidden"></div>
				</td>
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="surfaceLocation.path" cssClass="errors" />
				</td>
			</tr>
			<c:if test="${ not empty dynamicPathList }">
				<tr class="dynamic">
					<td style="padding:5px;" valign="top">Recently Found</td>
					<td style="padding:5px;" class="inputValue">
						<select style="width:350px;" size="5" onclick="$('#urlDynamicSearch').val(this.options[this.selectedIndex].value);" id="url_dynamic_select">
							<c:forEach var="path" items="${ dynamicPathList}">
								<option value="${ path }">
									<c:out value="${ path }"/>
								</option>
							</c:forEach>
						</select>
					</td>
				</tr>
			</c:if>
			<c:if test="${ not empty staticPathList }">
				<tr class="static">
					<td style="padding:5px;" valign="top">Recently Found</td>
					<td style="padding:5px;" class="inputValue">
						<select style="width:350px;" size="5" onclick="$('#urlStaticSearch').val(this.options[this.selectedIndex].value);" id="url_static_select">
							<c:forEach var="path" items="${ staticPathList}">
								<option value="${ path }">
									<c:out value="${ path }"/>
								</option>
							</c:forEach>
						</select>
					</td>
				</tr>
			</c:if>
			<tr class="static">
				<td style="padding:5px;">Line Number</td>
				<td style="padding:5px;" class="inputValue">
					<form:input style="width:350px;" path="dataFlowElements[0].lineNumber" id="urlSearch" name="urlSearch" alt="Search Criteria" 
							onkeyup="searchUrlSuggest(event);" autocomplete="off"  
							onKeyPress = "return disableEnterKey(event);"
							size="50" maxlength="255"/>
				</td>
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="dataFlowElements[0]" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td style="padding:5px;">Parameter</td>
				<td style="padding:5px;" class="inputValue">
					<form:input style="width:350px;" id="parameterInput" path="surfaceLocation.parameter" size="50" maxlength="127"/>
				</td>
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="surfaceLocation.parameter" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td style="padding:5px;">Severity</td>
				<td style="padding:5px;" class="inputValue">
					<form:select style="width:350px;" id="severityInput" path="channelSeverity.id">
						<form:options items="${ manualSeverities }" itemValue="id" itemLabel="code" />
					</form:select>
				</td>
			</tr>
			<tr>
				<td style="padding:5px;">Description</td>
				<td style="padding:5px;" class="inputValue">
					<form:textarea style="width:350px;" id="descriptionInput" path="longDescription" rows="5" cols="50"/>
				</td>
				<td style="padding:5px;" colspan="2" >
					<form:errors path="longDescription" cssClass="errors" />
				</td>
			</tr>
		</tbody>
	</table>
	</div>
	<div class="modal-footer">
		<button id="closeManualFindingModalButton" class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="dynamicSubmit" name="dynamicSubmit" data-success-div="modal-footer" class="modalSubmit btn btn-primary">Submit</a>
	</div>
</form:form>
