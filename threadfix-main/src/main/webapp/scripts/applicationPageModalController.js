var myAppModule = angular.module('threadfix')

myAppModule.controller('ApplicationPageModalController', function($scope, $rootScope, $window, $log, $http, $modal) {

    $scope.csrfToken = $scope.$parent.csrfToken;

    $scope.$watch('csrfToken', function() {
       $http.get($window.location.pathname + "/objects" + $scope.csrfToken).
           success(function(data, status, headers, config) {

               if (data.success) {
                   $scope.config = data.object;
                   $scope.config.application.organization = $scope.config.application.team;
               } else {
                   $log.info("HTTP request for form objects failed. Error was " + data.message);
               }
           }).
           error(function(data, status, headers, config) {
                $log.info("HTTP request for form objects failed.");
               // TODO improve error handling and pass something back to the users
               $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
           });
    });

    $scope.showEditModal = function() {

        var modalInstance = $modal.open({
            templateUrl: 'editApplicationModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    var app = $scope.config.application;
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/edit" + $scope.csrfToken;
                },
                object: function () {
                    var app = $scope.config.application;
                    app.deleteUrl = "/organizations/" + app.team.id + "/applications/" + app.id + "/delete" + $scope.csrfToken
                    return $scope.config.application;
                },
                config: function() {
                    return $scope.config;
                },
                buttonText: function() {
                    return "Save Changes";
                }
            }
        });

        modalInstance.result.then(function (application) {

            $scope.config.application = application;

            $scope.successMessage = "Successfully edited application " + application.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.$on('fileDragged', function(event, $files) {
        $scope.showUploadForm($files);
    });

    $scope.showUploadForm = function(files) {
        var modalInstance = $modal.open({
            templateUrl: 'uploadScanForm.html',
            controller: 'UploadScanController',
            resolve: {
                url: function() {
                    var app = $scope.config.application;
                    return "/organizations/" + app.team.id + "/applications/" + app.id + "/upload/remote" + $scope.csrfToken;
                },
                files: function() {
                    return files;
                }
            }
        });

        modalInstance.result.then(function (scan) {
            $log.info("Successfully uploaded scan.");
            $rootScope.$broadcast('scanUploaded');
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });

    }

})
