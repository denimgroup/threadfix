<script type="text/ng-template" id="uploadScanForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Upload Scan
        </h4>
    </div>

    <div ng-file-drop-available="dropSupported=true" ng-class="{ 'drop-box' : ready(), 'long-drop-box' : errorMessage }" ng-file-drop="onFileSelect($files)" class="modal-body">

        <div ng-show="waiting" class="modal-loading"><div><span class="spinner dark"></span>Processing...</div></div><br>

        <div ng-show="!dropSupported">HTML5 Drop File is not supported!<br>
            <div ng-show="errorMessage" class="alert alert-error">
                <button class="close" ng-click="errorMessage = false" type="button">x</button>
                {{ errorMessage }}
            </div>
            <div ng-show="ready()">
                Select File
                <input type="file" ng-file-select="onFileSelect($files)">
            </div>
        </div>

        <div ng-show="ready()" ng-show="dropSupported">
            <div ng-show="errorMessage" class="alert alert-error">
                <button class="close" ng-click="errorMessage = false" type="button">x</button>
                {{ errorMessage }}
            </div>

            Drag scan file here.
        </div>

        <progressbar ng-show="uploading" animate="false" value="dynamic" type="success"><b>{{uploadedPercent}}%</b></progressbar>
	</div>
	<div class="modal-footer">
		<span style="float:left;font-size:8;" class="errors">Average file uploads take a few seconds but <br>larger files (2GB+) can take several minutes.</span>
		<button id="closeScanModalButton" class="btn" ng-click="cancel()">Close</button>
	</div>
</script>
