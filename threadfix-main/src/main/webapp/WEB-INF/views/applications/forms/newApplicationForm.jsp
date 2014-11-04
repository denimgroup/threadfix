<script type="text/ng-template" id="newApplicationModal.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            New Application
        </h4>
    </div>

    <form id="newApplicationForm" name='form'>
        <div class="modal-body input-group">

            <table class="modal-form-table">
                <tr class="left-align">
                    <td>Name</td>
                    <td>
                        <input id="applicationNameInput" focus-on="focusInput" type='text' name='name' ng-model="object.name" ng-maxlength="60" required/>
                    </td>
                    <td>
                        <span id="applicationNameInputRequiredError" class="errors" ng-show="form.name.$dirty && form.name.$error.required">Name is required.</span>
                        <span id="applicationNameInputLengthError" class="errors" ng-show="form.name.$dirty && form.name.$error.maxlength">Maximum length is 60.</span>
                        <span id="applicationNameInputNameError" class="errors" ng-show="object.name_error"> {{ object.name_error }}</span>
                    </td>
                </tr>
                <tr class="left-align">
                    <td>URL</td>
                    <td>
                        <input id="applicationUrlInput" type='url' name='url' ng-model="object.url" ng-maxlength="255"/>
                    </td>
                    <td>
                        <span id="applicationUrlInputLengthError" class="errors" ng-show="form.url.$dirty && form.url.$error.maxlength">Maximum length is 255.</span>
                        <span id="applicationUrlInputInvalidUrlError" class="errors" ng-show="form.url.$dirty && form.url.$error.url">URL is invalid.</span>
                    </td>
                </tr>
                <tr class="left-align">
                    <td>Unique ID</td>
                    <td>
                        <input name="uniqueId" type='text' style="margin-bottom:0px;"
                               ng-model="object.uniqueId"
                               id="uniqueIdInput" size="50" maxlength="255"/>
                    </td>
                    <td>
                        <span id="uniqueIdLengthError" class="errors" ng-show="form.uniqueId.$dirty && form.uniqueId.$error.maxlength">Maximum length is 255.</span>
                    </td>
                </tr>
                <tr class="left-align">
                    <td>Team</td>
                    <td id="teamNameLabel">{{ object.team.name }}</td>
                </tr>
                <tr class="left-align">
                    <td>Criticality</td>
                    <td>
                        <select name="applicationCriticality.id"
                                style="margin-bottom:0px;"
                                ng-model="object.applicationCriticality.id"
                                id="criticalityIdSelect">

                            <c:forEach items="${applicationCriticalityList}" var="applicationCriticality">
                                <option value="<c:out value='${applicationCriticality.id}'/>">
                                    <c:out value='${applicationCriticality.name}'/>
                                </option>
                            </c:forEach>
                        </select>
                    </td>
                    <td>
                        <span class="errors" ng-show="object.applicationCriticality_id_error"> {{ object.applicationCriticality_id_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td class="right-align">Application Type</td>
                    <td class="left-align" >
                        <select name="frameworkType" ng-model="object.frameworkType" id="frameworkTypeSelect{{ object.team.id }}">
                            <c:forEach items="${applicationTypes}" var="type">
                                <option value="<c:out value='${type}'/>">
                                    <c:out value='${type}'/>
                                </option>
                            </c:forEach>
                        </select>
                    </td>
                </tr>
                <tr ng-init="loadTagsList()">
                    <td class="right-align">Tag</td>
                    <td class="left-align" >
                        <multi-select id="tagSelect"
                                input-model="tags"
                                output-model="object.tags"
                                button-label="name"
                                item-label="name"
                                tick-property="selected"
                                >
                        </multi-select>
                    </td>
                </tr>

                <tr>
                    <td colspan="2">
                        <a class="pointer" ng-click="sourceCodeDisplay = !sourceCodeDisplay">Source Code Information</a>
                    </td>
                </tr>
                <tr ng-show="sourceCodeDisplay">
                    <td class="right-align">Source Code URL</td>
                    <td class="left-align" >
                        <input name="repositoryUrl"
                                type='url' id="repositoryUrlInput"
                                maxlength="255" ng-model="object.repositoryUrl"/>
                    </td>
                    <td>
                        <span id="sourceUrlLengthError" class="errors" ng-show="form.repositoryUrl.$dirty && form.repositoryUrl.$error.maxlength">Maximum length is 255.</span>
                        <span id="sourceUrlValidError" class="errors" ng-show="form.repositoryUrl.$dirty && form.repositoryUrl.$error.url">URL is invalid.</span>
                    </td>
                </tr>
                <tr ng-show="sourceCodeDisplay">
                    <td>Source Code Revision</td>
                    <td>
                        <input type="text" id="repositoryBranch" ng-model="object.repositoryBranch" maxlength="250" name="repositoryBranch"/>
                    </td>
                    <td>
                        <span id="sourceRevisionLengthError" class="errors" ng-show="form.repositoryBranch.$dirty && form.repositoryBranch.$error.maxlength">Maximum length is 250.</span>
                    </td>
                </tr>
                <tr ng-show="sourceCodeDisplay">
                    <td>Source Code User Name</td>
                    <td>
                        <input type="text" id="repositoryUsername" ng-model="object.repositoryUserName" maxlength="250" name="repositoryUserName"/>
                    </td>
                    <td>
                        <span id="sourceUserNameLengthError" class="errors" ng-show="form.repositoryUserName.$dirty && form.repositoryUserName.$error.maxlength">Maximum length is 250.</span>
                    </td>
                </tr>
                <tr ng-show="sourceCodeDisplay">
                    <td>Source Code Password</td>
                    <td>
                        <input type="password" id="repositoryPassword" ng-model="object.repositoryPassword" showPassword="true" maxlength="250" name="repositoryPassword"/>
                    </td>
                    <td>
                        <span id="sourcePasswordLengthError" class="errors" ng-show="form.repositoryPassword.$dirty && form.repositoryPassword.$error.maxlength">Maximum length is 250.</span>
                    </td>
                </tr>
                <tr ng-show="sourceCodeDisplay">
                    <td class="right-align">Source Code Folder</td>
                    <td class="left-align" >
                        <input name="repositoryFolder"
                                type='text' id="repositoryFolderInput"
                                maxlength="250" ng-model="object.repositoryFolder"/>
                    </td>
                    <td>
                        <span id="sourceFolderLengthError" class="errors" ng-show="form.repositoryFolder.$dirty && form.repositoryFolder.$error.maxlength">Maximum length is 250.</span>
                        <span id="sourceFolderOtherError" class="errors" ng-show="object.repositoryFolder_error"> {{ object.repositoryFolder_error }}</span>
                    </td>
                </tr>
                <tr>
                    <td>Disable Vulnerability Merging</td>
                    <td class="inputValue">
                        <input id="skipApplicationMerge" type="checkbox" ng-model="object.skipApplicationMerge" name="skipApplicationMerge"/>
                        <a class="btn" popover="ThreadFix detects matching scan results and combine them in order to simplify the result set. This can make the number of vulnerabilities in ThreadFix lower than the number of results in a scan. Checking this box disables this behavior.">?</a>
                    </td>
                </tr>
            </table>

        </div>
        <%@ include file="/WEB-INF/views/modal/footer.jspf" %>
    </form>
</script>
