<script type="text/ng-template" id="newScheduledScan.html">

    <div class="modal-header">
		<h4>New Scheduled Scan</h4>
	</div>
    <div class="modal-body" ng-form="form">
        <table>
            <tr class="left-align">
                <td style="padding:5px;">Frequency</td>
                <td style="padding:5px;">
                    <select style="width:243px;" name="frequency" ng-model="object.frequency" id="frequency">
                        <option value="Daily">Daily</option>
                        <option value="Weekly">Weekly</option>
                    </select>
                </td>
            </tr>

            <tr class="left-align">
                <td style="padding:5px;">Time</td>
                <td style="padding:5px;">
                    <select name="hour" ng-model="object.hour" style="margin-bottom:0; width:60px;" id="hour">
                        <option value="0">12</option>
                        <option value="1">1</option>
                        <option value="2">2</option>
                        <option value="3">3</option>
                        <option value="4">4</option>
                        <option value="5">5</option>
                        <option value="6">6</option>
                        <option value="7">7</option>
                        <option value="8">8</option>
                        <option value="9">9</option>
                        <option value="10">10</option>
                        <option value="11">11</option>
                    </select>
                    :
                    <select name="minute" ng-model="object.minute" style="margin-bottom:0; width:60px;" id="minute">
                        <option value="0">00</option>
                        <option value="15">15</option>
                        <option value="30">30</option>
                        <option value="45">45</option>
                    </select>

                    <select style="margin-bottom:0; width:60px;"
                            name="selectedPeriod"
                            id="selectedPeriod"
                            ng-model="object.period"
                            name="period">
                        <option value="AM">AM</option>
                        <option value="PM">PM</option>
                    </select>

                    <select style="margin-bottom:0; width:110px;" name="selectedDay"
                                 id="selectedDay" ng-model="object.day"
                                 ng-show="object.frequency !== 'Daily'">
                        <option value="Sunday">Sunday</option>
                        <option value="Monday">Monday</option>
                        <option value="Tuesday">Tuesday</option>
                        <option value="Wednesday">Wednesday</option>
                        <option value="Thursday">Thursday</option>
                        <option value="Friday">Friday</option>
                        <option value="Saturday">Saturday</option>
                    </select>
                    <errors path="dateError" cssClass="errors" />
                    <span class="errors" ng-show="object.dateError_error"> {{ object.dateError_error }}</span>
                </td>
            </tr>

            <tr class="left-align">
                <td style="padding:5px;">Scanner</td>
                <td style="padding:5px;">
                    <select style="width:243px;" name="scanner" ng-model="object.scanner"
                                 id="scanner${application.id}">
                        <option ng-repeat='scanner in config.scanners' value="{{ scanner }}"> {{ scanner }} </option>
                    </select>
                    <errors path="scanner" cssClass="errors" />
                </td>
            </tr>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
