<script type="text/ng-template" id="uploadScanForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Upload Scan
        </h4>
    </div>

    <div
         ng-class="{ 'drop-box' : ready(), 'long-drop-box' : alerts.length != 0 }"
         ng-file-drop="onFileSelect($files)"
         ng-file-drop-available="isIE=false"
         class="modal-body">

        <div ng-show="waiting" class="modal-loading"><div><span class="spinner dark"></span>Processing...</div></div><br>

        <div ng-show="ready()">
            <div>
                <alert id="alert" ng-repeat="alert in alerts" type="alert.type" close="closeAlert($index)">{{alert.msg}}</alert>
            </div>
            <div ng-hide="isIE">
                Drag and drop scan files here.
            </div>
            <div ng-show="isIE">
                Select scans file.
            </div>
        </div>
        <span>Scans must be of the same type.</span>
        <progressbar ng-show="uploading" animate="false" value="dynamic" type="success"><b>{{uploadedPercent}}%</b></progressbar>
	</div>
    <div style="text-align:left" ng-show="ready()" class="modal-body">
        Select Scan
        <input id="scanFileInput" style="height:auto" type="file" ng-file-select="onFileSelect($files)" multiple="multiple">
    </div>
	<div class="modal-footer">
		<span style="float:left;font-size:8;" class="errors">Average file uploads take a few seconds but <br>larger files (2GB+) can take several minutes.</span>
		<button id="closeScanModalButton" class="btn" ng-click="cancel()">Close</button>
	</div>
</script>
