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
                    <form:select style="width:243px;" path="frequency" onchange="changeAbilityOfDaySelection()"
                                 id="frequency"
                                 items="${ frequencyTypes }"
                                 itemValue="description"
                                 itemLabel="description"/>
                    <form:errors path="frequency" cssClass="errors" />
                </td>
            </tr>

            <tr class="left-align">
                <td style="padding:5px;">Time</td>
                <td style="padding:5px;">
                    <form:select name="hour" style="margin-bottom:0px; width:52px;" id="hour${application.id}" path="hour">
                        <form:option value="0" label="0"/>
                        <form:option value="1" label="1"/>
                        <form:option value="2" label="2"/>
                        <form:option value="3" label="3"/>
                        <form:option value="4" label="4"/>
                        <form:option value="5" label="5"/>
                        <form:option value="6" label="6"/>
                        <form:option value="7" label="7"/>
                        <form:option value="8" label="8"/>
                        <form:option value="9" label="9"/>
                        <form:option value="10" label="10"/>
                        <form:option value="11" label="11"/>
                    </form:select>
                     :
                        <form:select name="minute" style="margin-bottom:0px; width:52px;" id="minute${application.id}" path="minute">
                            <form:option value="0" label="00"/>
                            <form:option value="15" label="15"/>
                            <form:option value="30" label="30"/>
                            <form:option value="45" label="45"/>
                        </form:select>

                    <form:select style="margin-bottom:0px; width:60px;"
                                 name="selectedPeriod"
                                 id="selectedPeriod${application.id}"
                                 path="period"
                                 items="${ periodTypes }"
                                 itemValue="period"
                                 itemLabel="period">
                    </form:select>

                    <form:select style="margin-bottom:0px; width:110px;" name="selectedDay"
                                 id="selectedDay"
                                 path="day" disabled="true">
                        <%--<form:option value="" label="Select Day"/>--%>
                        <form:options items="${ scheduledDays }" itemLabel="day" itemValue="day"/>
                    </form:select>
                    <form:errors path="dateError" cssClass="errors" />
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
