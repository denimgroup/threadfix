var myAppModule = angular.module('threadfix');

myAppModule.controller('ScanTableController', function ($scope, $window, $http, $log, $rootScope, tfEncoder, reportExporter) {

    var currentUrl = "/organizations/" + $scope.$parent.teamId + "/applications/" + $scope.$parent.appId;

    $scope.heading = '0 Scans';

    $scope.isIE = /*@cc_on!@*/false || !!document.documentMode;

    $scope.refresh = function() {

    };

    $scope.deleteScan = function(scan) {

        if (confirm('Are you sure you want to delete this scan?')) {

            scan.deleting = true;

            $http.post(tfEncoder.encode(currentUrl + '/scans/' + scan.id + '/delete')).
                success(function(data, status, headers, config) {

                    if (data.success) {
                        var index = $scope.scans.indexOf(scan);

                        if (index > -1) {
                            $scope.scans.splice(index, 1);
                        }

                        if ($scope.scans.length === 1) {
                            $scope.heading = '1 Scan';
                        } else {
                            $scope.heading = $scope.scans.length + " Scans";
                        }
                        $rootScope.$broadcast('scanDeleted', $scope.scans.length > 0);

                    } else {
                        scan.deleting = false;
                        $scope.errorMessage = "Something went wrong. " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $log.info("HTTP request for form objects failed.");
                    // TODO improve error handling and pass something back to the users
                    scan.deleting = false;
                    $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
                });
        }
    };

    $scope.downloadScan = function(scan) {

        scan.downloading = true;

        $http.post(tfEncoder.encode(currentUrl + '/scans/' + scan.id + '/download')).
            success(function(data, status, headers, config) {
                scan.downloading = false;

                if (data.success == false) {
                    $rootScope.$broadcast('downloadScanFail', data.message);
                } else {
                    reportExporter.exportScan(data, "application/octet-stream", scan.originalFileNames[0]);
                }

            }).
            error(function(data, status, headers, config) {
                $log.info("HTTP request for form objects failed.");
                $scope.errorMessage = "Failed to retrieve uploaded scan file. HTTP status was " + status;
                scan.downloading = false;
            });
    };

    $scope.viewScan = function(scan) {
        window.location.href = tfEncoder.encode(currentUrl + '/scans/' + scan.id);
    };

    $scope.$on('scans', function(event, scans) {
        $scope.scans = scans;
        if (!$scope.scans || !$scope.scans.length > 0) {
            $scope.scans = undefined;
        } else {
            if ($scope.scans.length === 1) {
                $scope.heading = '1 Scan';
            } else {
                $scope.heading = $scope.scans.length + ' Scans';
            }

            $scope.scansToDownload = false;
            scans.forEach(function(scan){
                if (scan.downloadable)
                    $scope.scansToDownload = true;
            })

        }

    });

});