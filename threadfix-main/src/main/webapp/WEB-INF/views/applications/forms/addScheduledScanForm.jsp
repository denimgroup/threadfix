<%@ include file="/common/taglibs.jsp"%>

	<div class="modal-header">
		<h4>New Scheduled Scan</h4>
	</div>
<spring:url value="/organizations/{orgId}/applications/{appId}/scheduledScans/addScheduledScan" var="submitUrl">
	<spring:param name="orgId" value="${ application.organization.id }"/>
	<spring:param name="appId" value="${ application.id }"/>
</spring:url>
<form:form id="scheduledScanForm${ application.id }" style="margin-bottom:0px" modelAttribute="scheduledScan" method="post" autocomplete="off" action="${ fn:escapeXml(submitUrl) }">
    <div class="modal-body">
        <table>
            <tr class="left-align">
                <td style="padding:5px;">Frequency</td>
                <td style="padding:5px;">
                    <form:select style="width:243px;" path="frequency"
                                 id="frequency${application.id}"
                                 items="${ frequencyTypes }"
                                 itemValue="description"
                                 itemLabel="description"/>
                    <form:errors path="frequency" cssClass="errors" />
                </td>
            </tr>

            <tr class="left-align">
                <td style="padding:5px;">Time</td>
                <td style="padding:5px;">
                    <form:input name="hour" style="margin-bottom:0px; width:22px;" id="hour${application.id}" size="1" maxlength="2" path="hour"/>
                     :
                    <form:input name="minute" style="margin-bottom:0px; width:22px;" id="minute${application.id}" size="1" maxlength="2" path="minute" />

                    <form:select style="margin-bottom:0px; width:60px;"
                                 name="selectedPeriod"
                                 id="selectedPeriod${application.id}"
                                 path="period"
                                 items="${ periodTypes }"
                                 itemValue="period"
                                 itemLabel="period">
                        <%--<c:forEach items="${periodTypes}" var="period">--%>
                            <%--<option value="${period.period}">${period.period}</option>--%>
                        <%--</c:forEach>--%>
                    </form:select>

                    <form:select style="margin-bottom:0px; width:110px;" name="selectedDay"
                                 id="selectedDay${application.id}"
                            path="day">
                        <form:option value="" label="Select Day"/>
                        <form:options items="${ scheduledDays }" itemLabel="day" itemValue="day"/>
                        <%--<c:forEach items="${scheduledDays}" var="dayInWeek">--%>
                            <%--<option value="${dayInWeek.day}">${dayInWeek.day}</option>--%>
                        <%--</c:forEach>--%>
                    </form:select>
                    <form:errors path="dateError" cssClass="errors" />
                    <%--<form:errors path="minute" cssClass="errors" />--%>
                    <%--<form:errors path="period" cssClass="errors" />--%>
                    <%--<form:errors path="day" cssClass="errors" />--%>
                </td>
            </tr>

            <tr class="left-align">
                <td style="padding:5px;">Scanner</td>
                <td style="padding:5px;">
                    <form:select style="width:243px;" path="scanner"
                                 id="scanner${application.id}"
                                 items="${ scannerTypeList }"/>
                    <form:errors path="scanner" cssClass="errors" />
                </td>
            </tr>
        </table>
    </div>
    <div class="modal-footer">
        <button class="btn" data-dismiss="modal" aria-hidden="true">Close</button>
        <a id="submitScheduledScanModal${application.id}" class="modalSubmit btn btn-primary"
           data-success-div="teamTable" data-success-click="teamCaret${ application.id }" data-form-div="addScheduledScan${ application.id }">Submit</a>
    </div>
</form:form>
