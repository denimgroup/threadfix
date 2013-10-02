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
					<c:set var="autocompleteJson" value='["'/>
					<c:set var="quote" value='"'/>					
					<c:forEach items="${ manualChannelVulnerabilities }" var="channelVulnerability">
						<c:set var="autocompleteJson" 
						value="${ autocompleteJson }${ quote }, ${ quote }${ fn:replace(channelVulnerability.name, '\\\\', '&#92;') } (CWE ${ channelVulnerability.genericVulnerability.id})"/>		
					</c:forEach>
					<c:set var="autocompleteJson" value="${ autocompleteJson }${ quote }]"/>
					<form:input style="width:350px"
							class="addAutocomplete" 
							path="channelVulnerability.code" 
							data-provide="typeahead"
							data-source ="${ autocompleteJson }"
							id="txtSearch" name="txtSearch"/>
				</td>
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="channelVulnerability.code" cssClass="errors" />
				</td>				
			</tr>
			<tr class="dynamic">
				<td style="padding:5px;">URL</td>
				<td style="padding:5px;" class="inputValue">
					<c:set var="autocompleteJson" value='["'/>
					<c:set var="quote" value='"'/>					
					<c:forEach items="${ urlManualList }" var="url">
						<c:set var="autocompleteJson" 
						value="${ autocompleteJson }${ quote }, ${ quote }${ fn:replace(url, '\\\\', '&#92;') }"/>		
					</c:forEach>
					<c:set var="autocompleteJson" value="${ autocompleteJson }${ quote }]"/>
					<form:input style="width:350px"
							class="addAutocomplete" 
							path="surfaceLocation.path" 
							data-provide="typeahead"
							data-source ="${ autocompleteJson }"
							id="urlDynamicSearch" name="urlDynamicSearch"/>
				</td>			
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="surfaceLocation.path" cssClass="errors" />
				</td>
			</tr>
			<tr class="static">
				<td style="padding:5px;">Source File</td>
				<td style="padding:5px;" class="inputValue">
					<c:set var="autocompleteJson" value='["'/>
					<c:set var="quote" value='"'/>					
					<c:forEach items="${ urlManualList }" var="source">
						<c:set var="autocompleteJson" 
						value="${ autocompleteJson }${ quote }, ${ quote }${ fn:replace(source, '\\\\', '&#92;') }"/>		
					</c:forEach>
					<c:set var="autocompleteJson" value="${ autocompleteJson }${ quote }]"/>
					<form:input style="width:350px"
							class="addAutocomplete" 
							path="dataFlowElements[0].sourceFileName" 
							data-provide="typeahead"
							data-source ="${ autocompleteJson }"
							id="urlStaticSearch" name="urlStaticSearch"/>
				</td>				
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="dataFlowElements[0].sourceFileName" cssClass="errors" />
				</td>
			</tr>
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
				<td/>
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
