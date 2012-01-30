<%@ include file="/common/taglibs.jsp"%>

<head>
    <title><c:out value="${ surveyResult.survey.name }" /></title>
</head>

<body id="apps">
	<h2><c:out value="${ surveyResult.survey.name }" /></h2>
	
	<table class="dataTable">
		<tbody>
			<tr>
				<td class="label">Team:</td>
				<td class="inputValue">
					<spring:url value="/organizations/{orgId}" var="orgUrl">
						<spring:param name="orgId" value="${ surveyResult.organization.id }"/>
					</spring:url>
					<a href="${ fn:escapeXml(orgUrl) }"><c:out value="${ surveyResult.organization.name }"/></a>
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
			</tr>
		</table>
		
		<table class="summary">
			<thead>
				<tr>
					<th>&nbsp;</th>
					<th style="width:30px;text-align:center"><b>Yes</b></th>
					<th style="width:30px;text-align:center"><b>No</b></th>
					<th style="text-align:center"><b>Comments</b></th>
				
				</tr>
			</thead>
			<tbody>
			<c:forEach var="section" items="${surveyResult.survey.surveySections}">
				<tr style="background: <c:out value='${section.color}' />" >
					<td colspan="4">
						<h2 style="color: #FFF;"><c:out value="${section.sectionName}" /></h2>
					</td>
				</tr>
				<c:forEach var="practice" items="${section.surveyPractices}">
					<tr style="background: <c:out value='${section.lightColor}' />" >
						<td colspan="4">
							<h3 style="color: <c:out value='${section.color}' />" ><c:out value="${practice.name}" /></h3>
						</td>
					</tr>
				<c:forEach var="level"  items="${surveyResult.survey.surveyLevels}">
					<tr style="background: <c:out value='${section.lightColor}' />" >
						<td colspan="4">
							<h4>Level - <c:out value="${level.number}" /></h4>
						</td>
					</tr>
				<c:forEach var="question" items="${practice.objectivesMap[level.number].surveyQuestions}">
					<c:set var="answer" value="${surveyResult.questionAnswers[question.id]}" />
					<c:set var="answerName" value="questionAnswers[${question.id}]" />
					<tr>
						<td><b>${question.surveyQuestion}</b></td>
						<td style="text-align:center">
							<input type="radio" name="<c:out value="${answerName}.answer" />" value="true"
								<c:if test="${answer.answer}">checked="checked"</c:if> 
							/>
						</td>
						<td style="text-align:center">
							<input type="radio" name="<c:out value="${answerName}.answer" />" value="false" 
								<c:if test="${!answer.answer}">checked="checked"</c:if>
							/>
						</td>
						<td style="padding-top:7px"><input type="text" name="<c:out value="${answerName}.comment" />" value="<c:out value='${answer.comment}' />" /></td>
					</tr>
				<c:forEach var="assertion" items="${question.surveyAssertions}" varStatus="row">
					<c:set var="answer" value="${surveyResult.assertionAnswers[assertion.id]}" />
					<c:set var="answerName" value="assertionAnswers[${assertion.id}]" />
					<tr>
						<td style="padding-left: 32px"><c:out value="${assertion.description}" /></td>
						<td style="text-align:center">
							<input type="checkbox" name="<c:out value="${answerName}.answer" />"
								<c:if test="${answer.answer}">checked="checked"</c:if> 
							/>
							<input type="hidden" name="<c:out value="_${answerName}.answer" />" />
						</td>
						<td></td>
						<td style="padding-top:7px;<c:if test='${fn:length(question.surveyAssertions)-1 == row.index}'>padding-bottom:7px;</c:if>"><input type="text" name="<c:out value="${answerName}.comment" />" value="<c:out value='${answer.comment}' />" /></td>
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