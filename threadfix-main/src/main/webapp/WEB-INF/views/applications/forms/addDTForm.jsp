<script type="text/ng-template" id="addDefectTrackerModal.html">

    <div class="modal-header">
        <h4 id="myModalLabel">Add Defect Tracker</h4>
        <div class="left-align" id="toReplaceDT"></div>
    </div>
    <div id="addDTFormDiv">
        <!-- TODO all of this stuff -->
        <!--<div id="addDefectTrackerDivInForm" class="modal-body">-->
            <!--<table>-->
                <!--<tr class="left-align">-->
                    <!--<td>Defect Tracker</td>-->
                    <!--<td class="inputValue">-->
                        <!--<c:if test="${ not empty defectTrackerList }">-->
                            <!--<select style="margin:5px;" id="defectTrackerId" name="defectTracker.id" onkeypress="enterPressHandler(event)">-->
                                <!--<option value="0">&lt;none&gt;</option>-->
                                <!--<c:forEach items="${ defectTrackerList }" var="listDefectTracker">-->
                                    <!--<c:choose>-->
                                        <!--<c:when test="${ not empty newDefectTracker && newDefectTracker.id == listDefectTracker.id}">-->
                                            <!--<option value="${ listDefectTracker.id }" selected="selected">-->
                                                <!--<c:out value="${ listDefectTracker.name }"/>-->
                                            <!--</option>-->
                                        <!--</c:when>-->
                                        <!--<c:when test="${ empty newDefectTracker && not empty application.defectTracker &&-->
                                                <!--application.defectTracker.id == listDefectTracker.id}">-->
                                            <!--<option value="${ listDefectTracker.id }" selected="selected">-->
                                                <!--<c:out value="${ listDefectTracker.name }"/>-->
                                            <!--</option>-->
                                        <!--</c:when>-->
                                        <!--<c:otherwise>-->
                                            <!--<option value="${ listDefectTracker.id }"><c:out value="${ listDefectTracker.name }"/></option>-->
                                        <!--</c:otherwise>-->
                                    <!--</c:choose>-->

                                <!--</c:forEach>-->
                            <!--</select>-->
                        <!--</c:if>-->
                    <!--</td>-->
                    <!--<td><c:if test="${ canManageDefectTrackers }"><a id="createDefectTrackerButtonInModal" href="#" class="btn" onclick="switchDTModals()">Create New Defect Tracker</a></c:if>	</td>-->
                    <!--<td style="padding-left:5px" colspan="2" >-->
                        <!--<form:errors path="defectTracker.id" cssClass="errors" />-->
                    <!--</td>-->
                <!--</tr>-->
                <!--<tr class="left-align">-->
                    <!--<td>Username</td>-->
                    <!--<td class="inputValue">-->
                        <!--<form:input style="margin:5px;" id="username" path="userName" size="50" maxlength="50" onkeypress="enterPressHandler(event)" />-->
                    <!--</td>-->
                    <!--<td style="padding-left:5px" colspan="2" >-->
                        <!--<form:errors path="userName" cssClass="errors" />-->
                    <!--</td>-->
                <!--</tr>-->
                <!--<tr class="left-align">-->
                    <!--<td>Password</td>-->
                    <!--<td class="inputValue">-->
                        <!--<form:password style="margin:5px;" id="password" showPassword="true" path="password" size="50" maxlength="50" onkeypress="enterPressHandler(event)"/>-->
                    <!--</td>-->
                    <!--<td style="padding-left:5px" colspan="2" >-->
                        <!--<form:errors path="password" cssClass="errors" />-->
                    <!--</td>-->
                <!--</tr>-->
                <!--<tr class="left-align">-->
                    <!--<td id="projectname" style="display:none">Product Name</td>-->
                    <!--<td class="inputValue">-->
                        <!--<form:select style="margin:5px; display:none;" id="projectList" path="projectName">-->
                            <!--<c:if test="${ not empty application.projectName }">-->
                                <!--<option value="${ application.projectName }"><c:out value="${ application.projectName }"/></option>-->
                            <!--</c:if>-->
                        <!--</form:select>-->
                    <!--</td>-->
                <!--</tr>-->
            <!--</table>-->
        <!--</div>-->
        <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
    </div>
</script>