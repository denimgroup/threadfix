<%@ include file="/common/taglibs.jsp"%>

	<div class="modal-header">
		<h4>Edit Finding</h4>
	</div>
<spring:url value="/organizations/{orgId}/applications/{appId}/vulnerabilities/{vulnerabilityId}/manual/{findingId}/edit" var="submitUrl">
    <spring:param name="orgId" value="${ vulnerability.application.organization.id }" />
    <spring:param name="appId" value="${ vulnerability.application.id }" />
    <spring:param name="vulnerabilityId" value="${ vulnerability.id }" />
    <spring:param name="findingId" value="${ finding.id }" />
</spring:url>	
<form:form id="manualFindingForm" style="margin-bottom:0px;" modelAttribute="finding" method="post" autocomplete="off" action="${ fn:escapeXml(submitUrl) }">
	<div class="modal-body">
	<table>
		<tbody>
			<tr>
					<td style="padding:5px;">
						<input id="dynamicRadioButton" type="radio" name="group" value="dynamic"
                            <c:if test="${ not finding.isStatic }">
                                checked
                            </c:if> />Dynamic
					</td>
					<td style="padding:5px;">
						<input id="staticRadioButton" type="radio" name="group" value="static"
                                <c:if test="${ finding.isStatic }">
                                    checked
                                </c:if> />Static
					</td>
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
                    <c:if test="${ not empty finding.channelVulnerability.code }">
                        <c:set var="cwe" value="${finding.channelVulnerability.code} (CWE ${ finding.channelVulnerability.genericVulnerability.id})"/>
                    </c:if>
					<form:input style="width:350px"
							class="addAutocomplete" 
							path="channelVulnerability.code" 
							data-provide="typeahead"
							data-source ="${ autocompleteJson }"
							id="txtSearch" name="txtSearch"
                            value="${cwe}" />

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
							id="urlDynamicSearch" name="urlDynamicSearch"
                            value="${finding.surfaceLocation.path}"/>
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
							id="urlStaticSearch" name="urlStaticSearch"
                            value="${finding.dataFlowElements[0].sourceFileName}"/>
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
							size="50" maxlength="255"
                            value="${finding.dataFlowElements[0].lineNumber}"/>
				</td>
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="dataFlowElements[0]" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td style="padding:5px;">Parameter</td>
				<td style="padding:5px;" class="inputValue">
					<form:input style="width:350px;"
                                id="parameterInput"
                                path="surfaceLocation.parameter"
                                size="50" maxlength="127"
                                value="${finding.surfaceLocation.parameter}"/>
				</td>
				<td style="padding:5px;" style="padding-left:5px" colspan="2" >
					<form:errors path="surfaceLocation.parameter" cssClass="errors" />
				</td>
			</tr>
			<tr>
				<td style="padding:5px;">Severity</td>
				<td style="padding:5px;" class="inputValue">
					<form:select style="width:350px;" id="severityInput" path="channelSeverity.id">
                        <c:forEach var="severity" items="${ manualSeverities }">
                            <option value="${ severity.id }"
                                    <c:if test="${ severity.code == finding.channelSeverity.code }">
                                        selected=selected
                                    </c:if>
                                    ><c:out value="${ severity.code }"/></option>
                        </c:forEach>
					</form:select>
				</td>
				<td/>
			</tr>
			<tr>
				<td style="padding:5px;">Description</td>
				<td style="padding:5px;" class="inputValue">
                    <textarea id="descriptionInput" name="longDescription" style="width:350px;" rows="5" cols="50"><c:out value="${ finding.longDescription }" /></textarea>
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
