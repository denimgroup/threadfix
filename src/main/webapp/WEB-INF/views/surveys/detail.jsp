<%@ include file="/common/taglibs.jsp"%>

<head>
    <title><c:out value="${surveyResult.survey.name}" /></title>
</head>

<body id="apps">
	<h2><c:out value="${surveyResult.survey.name}" /></h2>
	
	<table class="dataTable">
		<tr>
			<td class="label">Organization:</td>
			<td class="inputValue">
				<spring:url value="/organizations/{orgId}" var="orgUrl">
					<spring:param name="orgId" value="${ surveyResult.organization.id }"/>
				</spring:url>
				<a href="${ fn:escapeXml(orgUrl) }"><c:out value="${ surveyResult.organization.name }"/></a>
			</td>
		</tr>
		<tr>
			<td class="label">User:</td>
			<td class="inputValue"><c:out value="${ surveyResult.user }" /></td>
		</tr>
		<tr>
			<td class="label">Date:</td>
			<td class="inputValue"><c:out value="${ surveyResult.createdDate }" /></td>
		</tr>
	</table>
	<br/>
	
	<h3>Rankings</h3>
	<table class="summary">
		<thead>
			<tr>
				<th><em>Practice</em></th>
				<th style="width:60px;text-align:center"><em>Ranking</em></th>
				<th style="width:10px;text-align:center"><em>0</em></th>
				<th style="width:10px;text-align:center"><em>+</em></th>
				<c:forEach var="level" items="${surveyResult.survey.surveyLevels}">
					<th style="width:10px;text-align:center"><em><c:out value="${level.number}" /></em></th>
					<c:if test="${level.number < fn:length(surveyResult.survey.surveyLevels)}">
						<th style="width:10px;text-align:center"><em>+</em></th>
					</c:if>
				</c:forEach>
			</tr>
		</thead>
		<c:forEach var="section" items="${surveyResult.survey.surveySections}">
			<tr>
				<td colspan="${fn:length(surveyResult.survey.surveyLevels) * 2 + 3}"><h3 style="color: <c:out value='${section.color}' />"><c:out value="${section.sectionName}" /></h3></td>
			</tr>
			<c:forEach var="practice" items="${section.surveyPractices}">
				<tr style="background: <c:out value='${section.lightColor}'/>" >
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
				<th><em>Question</em></th>
				<th style="width:30px;text-align:center"><em>Yes</em></th>
				<th style="width:30px;text-align:center"><em>No</em></th>
				<th style="text-align:center"><em>Comments</em></th>
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
				<td>
					<h3 style="color: <c:out value='${section.color}' />" ><c:out value="${practice.name}" /></h3>
				</td>
				<td colspan="3" style="padding-left:5px">
					<h3>
						<c:out value="${surveyResult.practiceRankings[practice.id].level}" /> 
						<c:if test="${surveyResult.practiceRankings[practice.id].plus}">+</c:if>
					</h3>
				</td>
			</tr>
		<c:forEach var="level"  items="${surveyResult.survey.surveyLevels}">
			<tr style="background: <c:out value='${section.lightColor}' />">
				<td colspan="4">
					<c:set var="ranking" value="${surveyResult.practiceRankings[practice.id]}" />
					<c:choose>
						<c:when test="${ranking.level >= level.number}">
							<c:set var="iconImage" value="/images/icn_pass.png" />
						</c:when>
						<c:when test="${(ranking.level == (level.number - 1)) && ranking.plus}">
							<c:set var="iconImage" value="/images/icn_caution.png" />
						</c:when>
						<c:otherwise>
							<c:set var="iconImage" value="/images/icn_fail.png" />
						</c:otherwise>
					</c:choose>
					<img style="float: left; margin-right: 16px;" src="<c:url value='${iconImage}' />" />
					<h4>Level - <c:out value="${level.number}" /></h4>
				</td>
			</tr>
		<c:forEach var="question" items="${practice.objectivesMap[level.number].surveyQuestions}">
			<c:set var="answer" value="${surveyResult.questionAnswers[question.id]}" />
			<c:set var="answerName" value="questionAnswers[${question.id}]" />
			<tr>
				<td style="padding-top:7px"><b>${question.surveyQuestion}</b></td>
				<td style="text-align:center;padding-top:7px"><c:if test="${answer.answer}">X</c:if></td>
				<td style="text-align:center;padding-top:7px"><c:if test="${!answer.answer}">X</c:if></td>
				<td style="padding-top:7px"><c:out value="${answer.comment}"/></td>
			</tr>
		<c:forEach var="assertion" items="${question.surveyAssertions}" varStatus="row">
			<c:set var="answer" value="${surveyResult.assertionAnswers[assertion.id]}" />
			<c:set var="answerName" value="assertionAnswers[${assertion.id}]" />
			<tr>
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