<script type="text/ng-template" id="uploadScanForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Upload Scan
        </h4>
    </div>

    <div ng-file-drop-available="dropSupported=true"
         ng-class="{ 'drop-box' : ready(), 'long-drop-box' : alerts.length != 0 }"
         ng-file-drop="onFileSelect($files)"
         class="modal-body">

        <div ng-show="waiting" class="modal-loading"><div><span class="spinner dark"></span>Processing...</div></div><br>

        <div ng-show="ready()" ng-show="dropSupported">
            <div>
                <alert ng-repeat="alert in alerts" type="alert.type" close="closeAlert($index)">{{alert.msg}}</alert>
            </div>
            Drag and drop scan file here.
        </div>

        <progressbar ng-show="uploading" animate="false" value="dynamic" type="success"><b>{{uploadedPercent}}%</b></progressbar>
	</div>
    <div style="text-align:left" ng-show="ready()" class="modal-body">
        Select Scan
        <input style="height:auto" type="file" ng-file-select="onFileSelect($files)">
    </div>
	<div class="modal-footer">
		<span style="float:left;font-size:8;" class="errors">Average file uploads take a few seconds but <br>larger files (2GB+) can take several minutes.</span>
		<button id="closeScanModalButton" class="btn" ng-click="cancel()">Close</button>
	</div>
</script>
