<%@ include file="/common/taglibs.jsp"%>

<head>
    <title ng-non-bindable><c:out value="${ surveyResult.survey.name }" /></title>
    <cbs:cachebustscript src="/scripts/survey-sections.js"/>
</head>

<body id="apps">
	<h2 ng-non-bindable><c:out value="${ surveyResult.survey.name }" /></h2>
	
	<div id="helpText">The Software Assurance Maturity Model Interview Template was authored by Nick Coblentz. 
						<br> It is included here under the Creative Commons Attribution-ShareAlike 3.0 License.
						<br> To view a copy of this license, visit <a href="http://creativecommons.org/licenses/by-sa/3.0/">http://creativecommons.org/licenses/by-sa/3.0/</a>
						<br> The Software Assurance Maturity Model (SAMM) was created by Pravir Chandra.
	</div>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td>Team:</td>
				<td class="inputValue">
					<spring:url value="/organizations/{orgId}" var="orgUrl">
						<spring:param name="orgId" value="${ surveyResult.organization.id }"/>
					</spring:url>
					<a href="${ fn:escapeXml(orgUrl) }" onclick="return confirmExit();" ng-non-bindable><c:out value="${ surveyResult.organization.name }"/></a>
				</td>
			</tr>
		</tbody>
	</table>
	<br />
	
	<spring:url value="" var="emptyUrl"></spring:url>	
	<form:form modelAttribute="surveyResult" method="post" action="${ fn:escapeXml(emptyUrl) }">
		<table>
			<tr>
				<td>
					<input name="surveys/save" value="Save Assessment" type="submit" />
				</td>
				<td style="padding-left:10px">
					<input type="submit" value="Submit Assessment" />
				</td>
				<td style="padding-left:10px">
					<c:if test="${ saveConfirm }">
						<span style="font-weight: bold">Maturity Assessment saved successfully.</span>
					</c:if>
				</td>
				<td>
					<a href="${ fn:escapeXml(orgUrl) }" onclick="return confirmExit();">Return to Team Page</a>
				</td>
			</tr>
		</table>
		
		<table class="summary" id="table">
			<thead>
				<tr>
					<th class="toFix">&nbsp;</th>
					<th class="toFix" style="width:30px;text-align:center"><b>Yes</b></th>
					<th class="toFix" style="width:30px;text-align:center"><b>No</b></th>
					<th class="toFix" style="text-align:center"><b>Comments</b></th>
				</tr>
			</thead>
			<tbody ng-non-bindable>
			<c:forEach var="section" items="${surveyResult.survey.surveySections}">
				<tr style="background: <c:out value='${section.color}' />" >
					<td colspan="4">
						<h2 style="color: #FFF;padding-left:8px;padding-top:8px">
							<a style="color:white" href="javascript:toggle('section<c:out value='${section.id }'/>');">
								<c:out value="${section.sectionName}" />
							</a>
						</h2>
					</td>
				</tr>
				<c:forEach var="practice" items="${section.surveyPractices}">
					<tr class="section<c:out value="${ section.id }"/>" 
								style="background: <c:out value='${ section.lightColor }' />" >
						<td colspan="4">
							<h3 style="padding-left:8px;">
								<a style="color:<c:out value='${section.color}' />" href="javascript:toggle('practice<c:out value='${ practice.id }'/>');">
									<c:out value="${practice.name}" />
								</a>
							</h3>
						</td>
					</tr>
				<c:forEach var="level"  items="${surveyResult.survey.surveyLevels}">
					<tr class="section<c:out value="${ section.id }"/>  practice<c:out value="${ practice.id }"/>" 
								style="background:<c:out value='${section.lightColor}' />" >
						<td colspan="4">
							<h4 style="padding-left:8px;">Level - <c:out value="${level.number}" /></h4>
						</td>
					</tr>
				<c:forEach var="question" items="${practice.objectivesMap[level.number].surveyQuestions}">
					<c:set var="answer" value="${surveyResult.questionAnswers[question.id]}" />
					<c:set var="answerName" value="questionAnswers[${question.id}]" />
					<tr class="section<c:out value="${ section.id }"/>  practice<c:out value="${ practice.id }"/>">
						<td style="padding-left:8px"><b><c:out value="${question.surveyQuestion}"/></b></td>
						<td style="text-align:center">
							<input onchange="markEdited();" type="radio" name="<c:out value="${answerName}.answer" />" value="true"
								<c:if test="${answer.answer}">checked="checked"</c:if> 
							/>
						</td>
						<td style="text-align:center">
							<input onchange="markEdited();" type="radio" name="<c:out value="${answerName}.answer" />" value="false" 
								<c:if test="${!answer.answer}">checked="checked"</c:if>
							/>
						</td>
						<td style="padding-top:7px"><input type="text" name="<c:out value="${answerName}.comment" />" value="<c:out value='${answer.comment}' />" /></td>
					</tr>
				<c:forEach var="assertion" items="${question.surveyAssertions}" varStatus="row">
					<c:set var="answer" value="${surveyResult.assertionAnswers[assertion.id]}" />
					<c:set var="answerName" value="assertionAnswers[${assertion.id}]" />
					<tr class="section<c:out value="${ section.id }"/>  practice<c:out value="${ practice.id }"/>">
						<td style="padding-left: 32px"><c:out value="${assertion.description}" /></td>
						<td style="text-align:center">
							<input onchange="markEdited();" type="checkbox" name="<c:out value="${answerName}.answer" />"
								<c:if test="${answer.answer}">checked="checked"</c:if> 
							/>
							<input onchange="markEdited();" type="hidden" name="<c:out value="_${answerName}.answer" />" />
						</td>
						<td></td>
						<td style="padding-top:7px;<c:if test='${fn:length(question.surveyAssertions)-1 == row.index}'>padding-bottom:7px;</c:if>"><input onchange="markEdited();" type="text" name="<c:out value="${answerName}.comment" />" value="<c:out value='${answer.comment}' />" /></td>
					</tr>
				</c:forEach>
				</c:forEach>
				</c:forEach>
				</c:forEach>
			</c:forEach>
			</tbody>
		</table>
	</form:form>
</body>