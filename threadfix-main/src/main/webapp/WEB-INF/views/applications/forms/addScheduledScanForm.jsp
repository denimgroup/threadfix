<script type="text/ng-template" id="newScheduledScan.html">

    <div class="modal-header">
		<h4>New Scheduled Scan</h4>
	</div>
    <div class="modal-body" ng-form="form">
        <table class="modal-form-table">
            <tr class="left-align">
                <td style="padding:5px;">Frequency</td>
                <td style="padding:5px;">
                    <select style="width:243px;" name="frequency" ng-model="object.frequency" id="frequency">
                        <option ng-selected = "object.frequency==='Daily'" value="Daily">Daily</option>
                        <option ng-selected = "object.frequency==='Weekly'" value="Weekly">Weekly</option>
                    </select>
                </td>
            </tr>

            <tr class="left-align">
                <td style="padding:5px;">Time</td>
                <td style="padding:5px;">
                    <select name="hour" ng-model="object.hour" style="margin-bottom:0; width:60px;" id="hour">
                        <option ng-selected = "object.hour==='0'" value="0">12</option>
                        <option ng-selected = "object.hour==='1'" value="1">1</option>
                        <option ng-selected = "object.hour==='2'" value="2">2</option>
                        <option ng-selected = "object.hour==='3'" value="3">3</option>
                        <option ng-selected = "object.hour==='4'" value="4">4</option>
                        <option ng-selected = "object.hour==='5'" value="5">5</option>
                        <option ng-selected = "object.hour==='6'" value="6">6</option>
                        <option ng-selected = "object.hour==='7'" value="7">7</option>
                        <option ng-selected = "object.hour==='8'" value="8">8</option>
                        <option ng-selected = "object.hour==='9'" value="9">9</option>
                        <option ng-selected = "object.hour==='10'" value="10">10</option>
                        <option ng-selected = "object.hour==='11'" value="11">11</option>
                    </select>
                    :
                    <select name="minute" ng-model="object.minute" style="margin-bottom:0; width:60px;" id="minute">
                        <option ng-selected = "object.minute==='0'" value="0">00</option>
                        <option ng-selected = "object.minute==='15'" value="15">15</option>
                        <option ng-selected = "object.minute==='30'" value="30">30</option>
                        <option ng-selected = "object.minute==='45'" value="45">45</option>
                    </select>

                    <select style="margin-bottom:0; width:60px;"
                            name="selectedPeriod"
                            id="selectedPeriod"
                            ng-model="object.period"
                            name="period">
                        <option ng-selected = "object.period==='AM'" value="AM">AM</option>
                        <option ng-selected = "object.period==='PM'" value="PM">PM</option>
                    </select>

                    <select style="margin-bottom:0; width:110px;" name="selectedDay"
                                 id="selectedDay" ng-model="object.day"
                                 ng-show="object.frequency !== 'Daily'">
                        <option ng-selected = "object.day==='Sunday'" value="Sunday">Sunday</option>
                        <option ng-selected = "object.day==='Monday'" value="Monday">Monday</option>
                        <option ng-selected = "object.day==='Tuesday'" value="Tuesday">Tuesday</option>
                        <option ng-selected = "object.day==='Wednesday'" value="Wednesday">Wednesday</option>
                        <option ng-selected = "object.day==='Thursday'" value="Thursday">Thursday</option>
                        <option ng-selected = "object.day==='Friday'" value="Friday">Friday</option>
                        <option ng-selected = "object.day==='Saturday'" value="Saturday">Saturday</option>
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
                        <option ng-selected = "object.scanner === scanner" ng-repeat='scanner in config.scanners' value="{{ scanner }}"> {{ scanner }} </option>
                    </select>
                    <errors path="scanner" cssClass="errors" />
                </td>
            </tr>
            <tr>
                <td>Scan Config</td>
                <td>
                    <input id="defectId"
                           style="z-index:4000;width:300px"
                           type="text"
                           name = "id"
                           ng-model="object.scanConfig"
                           typeahead="document as (document.name + '.' + document.type) for document in config.documents | filter:$viewValue | limitTo:10"
                           typeahead-editable="true"
                           placeholder="Type file name"
                           class="form-control"/>
                    <a id="uploadDocScheduledScanModalLink${ application.id }" class="btn" ng-click="switchTo('addDocInScheduledScanModal')">Upload File</a>
                </td>
            </tr>
        </table>
        <div style="height:200px"></div>
    </div>
    <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
</script>
