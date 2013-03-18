<%@ include file="/common/taglibs.jsp"%>

<c:if test="${ not isStatic }">
	<input id="dynamicRadioButton" type="radio" name="group" value="dynamic" checked>Dynamic
	<input id="staticRadioButton" type="radio" name="group" value="static">Static
</c:if>
<c:if test="${ isStatic }">
	<input id="dynamicRadioButton" type="radio" name="group" value="dynamic">Dynamic
	<input id="staticRadioButton" type="radio" name="group" value="static" checked>Static
</c:if>
	
<spring:url value="" var="emptyUrl"></spring:url>	
<form:form style="margin-bottom:0px;" modelAttribute="finding" method="post" autocomplete="off" action="${ fn:escapeXml(emptyUrl) }">
	<table>
		<tbody>
			<tr>
				<td>Team</td>
				<td class="inputValue">
					<spring:url value="/organizations/{orgId}" var="orgUrl">
						<spring:param name="orgId" value="${ application.organization.id }"/>
					</spring:url>
					<a id="orgLink" href="${ fn:escapeXml(orgUrl) }"><c:out value="${ application.organization.name }"/></a>
				</td>
				<td colspan="2">&nbsp;</td>
			</tr>
			<tr>
				<td>Application</td>
				<td class="inputValue">
					<spring:url value="/organizations/{orgId}/applications/{appId}" var="appUrl">
						<spring:param name="orgId" value="${ application.organization.id }"/>
						<spring:param name="appId" value="${ application.id }"/>
					</spring:url>
					<a id="appLink" href="${ fn:escapeXml(appUrl) }"><c:out value="${ application.name }"/></a>
				</td>
				<td colspan="2">&nbsp;</td>
			</tr>
			<tr>
				<td>CWE</td>
				<td class="inputValue">
					<spring:url value="/organizations/{orgId}/applications/{appId}/scans/new/ajax_cwe" var="ajaxCweUrl">
						<spring:param name="orgId" value="${ application.organization.id }" />
						<spring:param name="appId" value="${ application.id }" />
					</spring:url>
					<input type="hidden" id="url1" value="${ fn:escapeXml(ajaxCweUrl)}"/>
					<form:input path="channelVulnerability.code" id="txtSearch" name="txtSearch" alt="Search Criteria" 
							onkeyup="searchCweSuggest(event);" autocomplete="off"  
							onKeyPress = "return disableEnterKey(event);"
							size="50" maxlength="255"/>
					<div id="search_cwe_suggest" class="search_suggest" style="visibility: hidden"></div>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="channelVulnerability.code" cssClass="errors" />
				</td>
			</tr>
			<c:if test="${ not empty staticChannelVulnerabilityList }">
				<tr class="static">
					<td valign="top">Recently Found</td>
					<td class="inputValue">
						<select size="5" onclick="$('#txtSearch').val(this.options[this.selectedIndex].value);" id="cv_static_select">
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
					<td valign="top">Recently Found</td>
					<td class="inputValue">
						<select onclick="$('#txtSearch').val(this.options[this.selectedIndex].value);" size="5" id="cv_dynamic_select">
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
				<td>URL</td>
				<td class="inputValue">
					<spring:url value="/organizations/{orgId}/applications/{appId}/scans/new/ajax_url" var="ajaxUrl">
						<spring:param name="orgId" value="${ application.organization.id }" />
						<spring:param name="appId" value="${ application.id }" />
					</spring:url>
					<input type="hidden" id="url2" value="${ fn:escapeXml(ajaxUrl)}"/>
					<form:input path="surfaceLocation.path" id="urlDynamicSearch" name="urlDynamicSearch" alt="Search Criteria" 
							onkeyup="searchUrlDynamicSuggest(event);" autocomplete="off"  
							onKeyPress = "return disableEnterKey(event);"
							size="50" maxlength="255"/>
					<div id="search_url_dynamic_suggest" class="search_suggest" style="visibility: hidden"></div>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="surfaceLocation.path" cssClass="errors" />
				</td>
			</tr>
			<tr class="static">
				<td>Source File</td>
				<td class="inputValue">
					<spring:url value="/organizations/{orgId}/applications/{appId}/scans/new/ajax_url" var="ajaxUrl">
						<spring:param name="orgId" value="${ application.organization.id }" />
						<spring:param name="appId" value="${ application.id }" />
					</spring:url>
					<input type="hidden" id="url2" value="${ fn:escapeXml(ajaxUrl)}"/>
					<form:input path="dataFlowElements[0].sourceFileName" id="urlStaticSearch" name="urlSearch" alt="Search Criteria" 
							onkeyup="searchUrlStaticSuggest(event);" autocomplete="off"  
							onKeyPress = "return disableEnterKey(event);"
							size="50" maxlength="255"/>
					<div id="search_url_static_suggest" class="search_suggest" style="visibility: hidden"></div>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="surfaceLocation.path" cssClass="errors" />
				</td>
			</tr>
			<c:if test="${ not empty dynamicPathList }">
				<tr class="dynamic">
					<td valign="top">Recently Found</td>
					<td class="inputValue">
						<select size="5" onclick="$('#urlDynamicSearch').val(this.options[this.selectedIndex].value);" id="url_dynamic_select">
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
					<td valign="top">Recently Found</td>
					<td class="inputValue">
						<select size="5" onclick="$('#urlStaticSearch').val(this.options[this.selectedIndex].value);" id="url_static_select">
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
				<td>Line Number</td>
				<td class="inputValue">
					<form:input path="dataFlowElements[0].lineNumber" id="urlSearch" name="urlSearch" alt="Search Criteria" 
							onkeyup="searchUrlSuggest(event);" autocomplete="off"  
							onKeyPress = "return disableEnterKey(event);"
							size="50" maxlength="255"/>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="dataFlowElements[0]" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>Parameter</td>
				<td class="inputValue">
					<form:input id="parameterInput" path="surfaceLocation.parameter" size="50" maxlength="127"/>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="surfaceLocation.parameter" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td>Severity</td>
				<td class="inputValue">
					<form:select id="severityInput" path="channelSeverity.id">
						<form:options items="${ channelSeverityList }" itemValue="id" itemLabel="code" />
					</form:select>
				</td>
			</tr>
			<tr>
				<td>Description</td>
				<td class="inputValue">
					<form:textarea id="descriptionInput" path="longDescription" rows="5" cols="50"/>
				</td>
				<td style="padding-left:5px" colspan="2" >
					<form:errors path="longDescription" cssClass="errors" />
				</td>
			</tr>
		</tbody>
	</table>
	<br/>
	<input class="btn" type="submit" id="dynamicSubmit" name="dynamicSubmit" class="dynamic" value="Submit"/>
	<input class="btn" type="submit" id="staticSubmit" name="staticSubmit" class="static" value="Submit"/>
	<div class="modal-footer">
		<button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
		<a id="submitDTModal" class="btn btn-primary" onclick="javascript:submitManualFinding('<c:out value="${saveUrl }"/>');return false;">Submit Finding</a>
	</div>
</form:form>