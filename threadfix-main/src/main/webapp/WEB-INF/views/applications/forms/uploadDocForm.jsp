<script type="text/ng-template" id="uploadDocumentForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Upload Document
        </h4>
    </div>
	<div ng-form="form" class="modal-body" ng-file-drop="onFileSelect($files)">

        <div ng-show="waiting" class="modal-loading"><div><span class="spinner dark"></span>Processing...</div></div><br>
        <div>
            <alert ng-repeat="alert in alerts" type="alert.type" close="closeAlert($index)">{{alert.msg}}</alert>
        </div>
        <progressbar ng-show="uploading" animate="false" value="dynamic" type="success"><b>{{uploadedPercent}}%</b></progressbar>

        <table ng-hide="waiting || uploading">
			<tr>
				<td class="right-align" style="padding:5px;">File</td>
				<td class="left-align" style="padding:5px;"><input id="docFileInput" type="file" name="file" size="50" ng-file-select="onFileSelect($files)"/></td>
			</tr>
		</table>
	</div>
	<div class="modal-footer">
		<span style="float:left;font-size:8;" class="errors">Average file uploads take a few seconds but <br>larger files (2GB+) can take several minutes.</span>
        <a class="btn" ng-click="cancel()">Close</a>
	</div>
</script>