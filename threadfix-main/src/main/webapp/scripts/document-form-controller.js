var myAppModule = angular.module('threadfix')

myAppModule.controller('DocumentFormController', function ($scope, $window, $modal, $http, $log, $rootScope) {

    $scope.heading = '0 Files';

    $scope.base = window.location.pathname;

    $scope.showUploadForm = function() {
        $scope.$emit('dragOff');
        var modalInstance = $modal.open({
            templateUrl: 'uploadDocumentForm.html',
            controller: 'UploadScanController',
            resolve: {
                url: function() {
                    return window.location.pathname + "/documents/upload" + $scope.csrfToken;
                },
                files: function() {
                    return undefined;
                }
            }
        });

        modalInstance.result.then(function (document) {
            if (!$scope.documents) {
                $scope.documents = [];
            }
            $scope.documents.push(document);
            $scope.successMessage = "Successfully uploaded document" + application.name;
            $scope.$emit('dragOn');

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
            $scope.$emit('dragOn');

        });
    }

    $scope.deleteFile = function(document) {

        document.deleting = true;

        if (confirm('Are you sure you want to delete this file?')) {
            $http.post($window.location.pathname + '/documents/' + document.id + '/delete' + $scope.csrfToken).
                success(function(data, status, headers, config) {

                    if (data.success) {
                        var index = $scope.documents.indexOf(document);

                        if (index > -1) {
                            $scope.documents.splice(index, 1);
                        }

                        if ($scope.documents.length === 0) {
                            $scope.heading = '0 Files';
                            $scope.documents = undefined;
                        }
                        $rootScope.$broadcast('scanDeleted', $scope.scans.length > 0);

                    } else {
                        document.deleting = false;
                        $scope.errorMessage = "Something went wrong. " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $log.info("HTTP request for form objects failed.");
                    // TODO improve error handling and pass something back to the users
                    document.deleting = false;
                    $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
                });
        }
    };

    $scope.downloadDocument = function(scan) {
        $http.post($window.location.pathname + '/documents/' + scan.id + '/delete' + $scope.csrfToken).
            success(function(data, status, headers, config) {

                if (data.success) {
                    var index = $scope.documents.indexOf(scan);

                    if (index > -1) {
                        $scope.documents.splice(index, 1);
                    }

                    if ($scope.documents.length === 0) {
                        $scope.heading = '0 Files';
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
            });    };

    $scope.viewDocument = function(scan) {
        window.location.href = $window.location.pathname + '/scans/' + scan.id + $scope.csrfToken;
    };

    $scope.$on('documents', function(event, documents) {
        $scope.documents = documents;
        if (!$scope.documents || !$scope.documents.length > 0) {
            $scope.documents = undefined;
        } else {
            if ($scope.documents.length === 1) {
                $scope.heading = '1 Files';
            } else {
                $scope.heading = $scope.documents.length + ' Files';
            }
        }

    });


});