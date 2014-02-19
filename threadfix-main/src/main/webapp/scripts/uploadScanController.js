var myAppModule = angular.module('threadfix')

myAppModule.controller('UploadScanController', function ($scope, $modalInstance, threadFixModalService, files, url, $upload) {

    $scope.uploading = false;

    $scope.uploadedPercent = 0;

    $scope.ready = function() {
        return !$scope.uploading && !$scope.waiting;
    }

    $scope.onFileSelect = function($files) {
        $scope.uploading = true;

        //$files: an array of files selected, each file has name, size, and type.
        for (var i = 0; i < $files.length; i++) {
            var file = $files[i];
            $scope.upload = $upload.upload({
                url: url,
                method: "POST",
                // headers: {'headerKey': 'headerValue'},
                // withCredentials: true,
                file: file
                // file: $files, //upload multiple files, this feature only works in HTML5 FromData browsers
                /* set file formData name for 'Content-Desposition' header. Default: 'file' */
                //fileFormDataName: myFile, //OR for HTML5 multiple upload only a list: ['name1', 'name2', ...]
                /* customize how data is added to formData. See #40#issuecomment-28612000 for example */
                //formDataAppender: function(formData, key, val){} //#40#issuecomment-28612000
            }).progress(function(evt) {
                $scope.uploadedPercent = parseInt(100.0 * evt.loaded / evt.total);
                if ($scope.uploading && $scope.uploadedPercent == 100) {
                    $scope.uploading = false;
                    $scope.waiting = true;
                }
            }).success(function(data, status, headers, config) {
                if (data.success) {
                    $modalInstance.close(data.object); // pass the team back up to update stats
                } else {
                    $scope.errorMessage = data.message;
                    $scope.showError = true;
                    $scope.waiting = false;
                    $scope.uploading = false;
                }
            });
        }
    };

    if (files) {
        $scope.onFileSelect(files);
    }

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };
});
