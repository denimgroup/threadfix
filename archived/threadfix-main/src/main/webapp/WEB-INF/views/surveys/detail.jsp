<%@ include file="/common/taglibs.jsp"%>

<head>
    <title ng-non-bindable><c:out value="${surveyResult.survey.name}" /></title>
    <cbs:cachebustscript src="/scripts/survey-sections.js"/>
</head>

<body id="apps">
	<h2 ng-non-bindable><c:out value="${surveyResult.survey.name}" /></h2>
	
	<table class="dataTable">
		<tr>
			<td>Team:</td>
			<td class="inputValue">
				<spring:url value="/organizations/{orgId}" var="orgUrl">
					<spring:param name="orgId" value="${ surveyResult.organization.id }"/>
				</spring:url>
				<a href="${ fn:escapeXml(orgUrl) }" ng-non-bindable><c:out value="${ surveyResult.organization.name }"/></a>
			</td>
		</tr>
		<tr>
			<td>User:</td>
			<td class="inputValue" ng-non-bindable><c:out value="${ surveyResult.user }" /></td>
		</tr>
		<tr>
			<td>Date:</td>
			<td class="inputValue" ng-non-bindable><c:out value="${ surveyResult.createdDate }" /></td>
		</tr>
	</table>
	<br/>
	
	<h3>Rankings</h3>
	<table class="summary">
		<thead>
			<tr>
				<th><em>Practice</em></th>
				<th style="width:60px;text-align:center"><em>Ranking</em></th>
				<th style="width:20px;text-align:center"><em>0</em></th>
				<th style="width:20px;text-align:center"><em>+</em></th>
				<c:forEach var="level" items="${surveyResult.survey.surveyLevels}">
					<th style="width:20px;text-align:center"><em ng-non-bindable><c:out value="${level.number}" /></em></th>
					<c:if test="${level.number < fn:length(surveyResult.survey.surveyLevels)}">
						<th style="width:20px;text-align:center"><em>+</em></th>
					</c:if>
				</c:forEach>
			</tr>
		</thead>
		<c:forEach var="section" items="${surveyResult.survey.surveySections}">
			<tr>
				<td colspan="${fn:length(surveyResult.survey.surveyLevels) * 2 + 3}"><h3 ng-non-bindable style="color: <c:out value='${section.color}' />"><c:out value="${section.sectionName}" /></h3></td>
			</tr>
			<c:forEach var="practice" items="${section.surveyPractices}">
				<tr ng-non-bindable style="background: <c:out value='${section.lightColor}'/>" >
					<td><c:out value="${practice.name}" /></td>
					<td style="text-align:center">
						<c:set var="ranking" value="${surveyResult.practiceRankings[practice.id]}" />
						<c:out value="${ranking.level}" />
						<c:if test="${ranking.plus}">+</c:if>
					</td>
					<td style="background: <c:out value="${section.color}" />">&nbsp;</td>
			<c:choose>
				<c:when test="${ ranking.level > 0 || ranking.plus }">
					<td style="background: <c:out value="${section.color}" />">&nbsp;</td>
				</c:when>
				<c:otherwise>
					<td>&nbsp;</td>
				</c:otherwise>
			</c:choose>
		<c:forEach var="level" items="${surveyResult.survey.surveyLevels}">
			<c:choose>
				<c:when test="${ranking.level >= level.number}">
					<td style="background: <c:out value="${section.color}" />">&nbsp;</td>
				</c:when>
				<c:otherwise>
					<td>&nbsp;</td>
				</c:otherwise>
			</c:choose>
		<c:if test="${level.number < fn:length(surveyResult.survey.surveyLevels)}">
			<c:choose>
				<c:when test="${(ranking.level > level.number) || (ranking.level == level.number && ranking.plus)}">
					<td style="background: <c:out value="${section.color}" />">&nbsp;</td>
				</c:when>
				<c:otherwise>
					<td>&nbsp;</td>
				</c:otherwise>
			</c:choose>
		</c:if>
			</c:forEach>
				</tr>
			</c:forEach>
		</c:forEach>
	</table>
	<br/>
	
	<h3>Survey Answers</h3>
	<table class="summary">
		<thead>
			<tr>
				<th class="toFix"><em>Question</em></th>
				<th class="toFix" style="width:30px;text-align:center"><em>Yes</em></th>
				<th class="toFix" style="width:30px;text-align:center"><em>No</em></th>
				<th class="toFix" style="text-align:center"><em>Comments</em></th>
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
			<tr class="section<c:out value="${ section.id }"/>"  style="background: <c:out value='${section.lightColor}' />" >
				<td>
					<h3 style="padding-left:8px;">
						<a style="color:<c:out value='${section.color}' />" href="javascript:toggle('practice<c:out value='${ practice.id }'/>');">
							<c:out value="${practice.name}" />
						</a>
					</h3>
				</td>
				<td colspan="3" style="padding-left:5px">
					<h3>
						<c:out value="${surveyResult.practiceRankings[practice.id].level}" /> 
						<c:if test="${surveyResult.practiceRankings[practice.id].plus}">+</c:if>
					</h3>
				</td>
			</tr>
		<c:forEach var="level"  items="${surveyResult.survey.surveyLevels}">
			<tr class="section<c:out value="${ section.id }"/>  practice<c:out value="${ practice.id }"/>"
						style="background: <c:out value='${section.lightColor}' />">
				<td colspan="4">
					<c:set var="ranking" value="${surveyResult.practiceRankings[practice.id]}" />
					<c:choose>
						<c:when test="${ranking.level >= level.number}">
							<div style="color:green;padding-left:8px;">Pass</div>
						</c:when>
						<c:when test="${(ranking.level == (level.number - 1)) && ranking.plus}">
							<div style="color:blue;padding-left:8px;">Caution</div>
						</c:when>
						<c:otherwise>
							<div style="color:red;padding-left:8px;">Fail</div>
						</c:otherwise>
					</c:choose>
					<h4 style="padding-left:8px;">Level - <c:out value="${level.number}" /></h4>
				</td>
			</tr>
		<c:forEach var="question" items="${practice.objectivesMap[level.number].surveyQuestions}">
			<c:set var="answer" value="${surveyResult.questionAnswers[question.id]}" />
			<c:set var="answerName" value="questionAnswers[${question.id}]" />
			<tr class="section<c:out value="${ section.id }"/>  practice<c:out value="${ practice.id }"/>">
				<td style="padding-top:7px;padding-left:8px"><b><c:out value="${question.surveyQuestion}"/></b></td>
				<td style="text-align:center;padding-top:7px"><c:if test="${answer.answer}">X</c:if></td>
				<td style="text-align:center;padding-top:7px"><c:if test="${!answer.answer}">X</c:if></td>
				<td style="padding-top:7px"><c:out value="${answer.comment}"/></td>
			</tr>
		<c:forEach var="assertion" items="${question.surveyAssertions}" varStatus="row">
			<c:set var="answer" value="${surveyResult.assertionAnswers[assertion.id]}" />
			<c:set var="answerName" value="assertionAnswers[${assertion.id}]" />
			<tr class="section<c:out value="${ section.id }"/>  practice<c:out value="${ practice.id }"/>">
				<td style="padding-left: 32px; padding-top:7px;<c:if test='${fn:length(question.surveyAssertions)-1 == row.index}'>padding-bottom:7px;</c:if>"><c:out value="${assertion.description}" /></td>
				<td style="text-align:center;padding-top:7px;<c:if test='${fn:length(question.surveyAssertions)-1 == row.index}'>padding-bottom:7px;</c:if>">
					<c:if test="${answer.answer}">X</c:if>
				</td>
				<td style="padding-top:7px;<c:if test='${fn:length(question.surveyAssertions)-1 == row.index}'>padding-bottom:7px;</c:if>"></td>
				<td style="padding-top:7px;<c:if test='${fn:length(question.surveyAssertions)-1 == row.index}'>padding-bottom:7px;</c:if>"><c:out value="${answer.comment}"/></td>
			</tr>
		</c:forEach>
		</c:forEach>
		</c:forEach>
		</c:forEach>
		</c:forEach>
		</tbody>
	</table>
</body>