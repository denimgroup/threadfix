var myAppModule = angular.module('threadfix')

myAppModule.controller('DocumentFormController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder) {

    $scope.heading = '0 Files';

    $scope.base = window.location.pathname;

    $scope.currentUrl = $scope.$parent.currentUrl;

    $scope.showUploadForm = function() {
        $scope.$emit('dragOff');
        var modalInstance = $modal.open({
            templateUrl: 'uploadDocumentForm.html',
            controller: 'UploadScanController',
            resolve: {
                url: function() {
                    return $scope.currentUrl + "/documents/upload";
                },
                files: function() {
                    return undefined;
                }
            }
        });

        modalInstance.result.then(function (document) {
            if (!$scope.documents || $scope.documents.length === 0) {
                $scope.documents = [];
            }
            $scope.documents.push(document);
            $scope.heading = $scope.documents.length + ' Files';
            $scope.$parent.successMessage = "Successfully uploaded document " + document.name;
            $scope.$emit('dragOn');

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
            $scope.$emit('dragOn');

        });
    }

    $scope.deleteFile = function(document) {

        if (confirm('Are you sure you want to delete this file?')) {
            document.deleting = true;
            $http.post(tfEncoder.encode($scope.currentUrl + '/documents/' + document.id + '/delete')).
                success(function(data, status, headers, config) {

                    if (data.success) {
                        var index = $scope.documents.indexOf(document);

                        if (index > -1) {
                            $scope.documents.splice(index, 1);
                        }

                        if ($scope.documents.length === 0) {
                            $scope.heading = '0 Files';
                            $scope.documents = undefined;
                        } else {
                            $scope.heading = $scope.documents.length + ' Files';
                        }
                        $scope.$parent.successMessage = "Successfully deleted document " + document.name;

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

    $scope.downloadDocument = function(document) {
        $http.post(tfEncoder.encode($scope.currentUrl + '/documents/' + document.id + '/download')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    var index = $scope.documents.indexOf(scan);

                    if (index > -1) {
                        $scope.documents.splice(index, 1);
                    }

                    if ($scope.documents.length === 0) {
                        $scope.heading = '0 Files';
                    }

                } else {
                    $scope.errorMessage = "Something went wrong. " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $log.info("HTTP request for form objects failed.");
                // TODO improve error handling and pass something back to the users
                $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
            });
    };

    $scope.viewDocument = function(document) {
        window.location.href = tfEncoder.encode($scope.currentUrl + '/documents/' + document.id);
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