<script type="text/ng-template" id="uploadScanForm.html">
    <div class="modal-header">
        <h4 id="myModalLabel">
            Upload Scan
        </h4>
    </div>

    <div ng-hide="confirmingScanUploadStyle">
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
                    Select scan files.
                </div>
            </div>
            <progressbar ng-show="uploading" animate="false" value="dynamic" type="success"><b>{{uploadedPercent}}%</b></progressbar>
        </div>
        <div style="text-align:left" ng-show="ready()" class="modal-body">
            Select Scan
            <input id="scanFileInput" style="height:auto" type="file" ng-file-select="onFileSelect($files)" multiple="multiple">
        </div>
    </div>

    <div ng-show="confirmingScanUploadStyle" class="multi-upload-div">

        <div class="modal-loading"></div><div>Please choose an upload method.</div><br>

        <button id="singleScan"
                class="btn btn-primary"
                ng-click="uploadAsMultiScans(false)">
            Upload As Single Scan
        </button>
        <button id="submit"
                class="btn btn-primary"
                ng-click="uploadAsMultiScans(true)">
            Upload As Multiple Scans
        </button>
    </div>

    <div class="modal-footer">
        <span style="float:left;font-size:8;" class="errors">Average file uploads take a few seconds but <br>larger files (2GB+) can take several minutes.</span>
        <button id="closeScanModalButton" class="btn" ng-click="cancel()">Close</button>
    </div>
</script>
