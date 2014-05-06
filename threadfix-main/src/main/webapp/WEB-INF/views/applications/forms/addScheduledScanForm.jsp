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
                    <select name="hour" ng-model="object.hour" style="margin-bottom:0; width:52px;" id="hour" name="hour">
                        <option value="0" label="0"/>
                        <option value="1" label="1"/>
                        <option value="2" label="2"/>
                        <option value="3" label="3"/>
                        <option value="4" label="4"/>
                        <option value="5" label="5"/>
                        <option value="6" label="6"/>
                        <option value="7" label="7"/>
                        <option value="8" label="8"/>
                        <option value="9" label="9"/>
                        <option value="10" label="10"/>
                        <option value="11" label="11"/>
                    </select>
                     :
                    <select name="minute" ng-model="object.minute" style="margin-bottom:0; width:52px;" id="minute" name="minute">
                        <option value="0" label="00"/>
                        <option value="15" label="15"/>
                        <option value="30" label="30"/>
                        <option value="45" label="45"/>
                    </select>

                    <select style="margin-bottom:0; width:60px;"
                                 name="selectedPeriod"
                                 id="selectedPeriod"
                                 ng-model="object.period"
                                 name="period">
                        <option value="AM" label="AM"/>
                        <option value="PM" label="PM"/>
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
                                 id="scanner${application.id}"/>
                        <option ng-repeat='scanner in config.scanners' value="{{ scanner }}"> {{ scanner }} </option>
                    </select>
                    <errors path="scanner" cssClass="errors" />
                </td>
            </tr>
        </table>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>