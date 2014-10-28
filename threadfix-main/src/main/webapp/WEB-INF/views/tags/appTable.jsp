<div>

	<h4 style="padding-top:10px">Tagged Applications</h4>

    <%--<div ng-form="mappedForm" class="pagination" ng-show="numApps > 100">--%>
        <%--<pagination class="no-margin" total-items="numApps / 10" max-size="5" page="page"></pagination>--%>

        <%--<input name="pageMappedInput"  ng-enter="goToPage(mappedForm.$valid)" style="width:50px" type="number" ng-model="pageInput" max="{{numberOfMappedPages * 1}}" min="1"/>--%>
        <%--<button class="btn" ng-class="{ disabled : mappedForm.$invalid }" ng-click="goToPage(mappedForm.$valid)"> Go to Page </button>--%>
        <%--<span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.min || mappedForm.pageMappedInput.$error.max">Input number from 1 to {{numberOfMappedPages}}</span>--%>
        <%--<span class="errors" ng-show="mappedForm.pageMappedInput.$dirty && mappedForm.pageMappedInput.$error.number">Not a valid number</span>--%>
    <%--</div>--%>

    <div ng-show="loading" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <table class="table tf-colors" id="1">
		<thead>
			<tr>
				<th class="first">Application</th>
				<th class="last">Team</th>
			</tr>
		</thead>
		<tbody>

        <tr ng-hide="appList || loading" class="bodyRow">
            <td colspan="2" style="text-align: center;"> No Applications were tagged to this Tag.</td>
        </tr>

        <tr ng-repeat="app in appList" class="bodyRow" >
            <td class="pointer" id="app{{ $index }}"> <a ng-click="goToApp(app)">{{app.name}}</a></td>
            <td class="pointer" id="team{{ $index }}"><a ng-click="goToTeam(app)">{{app.team.name}}</a></td>
        </tr>
		</tbody>
	</table>
</div>