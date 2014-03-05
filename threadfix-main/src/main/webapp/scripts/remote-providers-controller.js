var module = angular.module('threadfix')

module.controller('RemoteProvidersController', function($scope, $http, $modal, $log){

    $scope.providers = [];

    $scope.initialized = false;

    $scope.empty = true;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$watch('csrfToken', function() {
        $http.get('/configuration/remoteproviders/getMap' + $scope.csrfToken).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.providers = data.object.remoteProviders;
                    $scope.teams = data.object.teams;

                    $scope.empty = $scope.providers.length === 0;

                    $scope.defectTrackerTypes = data.object.defectTrackerTypes;

                    $scope.providers.sort(nameCompare);
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.configure = function(provider) {
        var modalInstance = $modal.open({
            templateUrl: 'configureRemoteProviderModal.html',
            controller: 'RemoteProviderModalController',
            resolve: {
                url: function() {
                    return "/configuration/remoteproviders/" + provider.id + "/configure" + $scope.csrfToken;
                },
                type: function() {
                    return provider;
                },
                config: function() {
                    return {
                        trackerTypes: $scope.defectTrackerTypes
                    };
                },
                buttonText: function() {
                    return "Create Defect Tracker";
                }
            }
        });

        modalInstance.result.then(function (newTracker) {

            $scope.successMessage = "Successfully edited tracker " + newTracker.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openAppModal = function(tracker) {
        var modalInstance = $modal.open({
            templateUrl: 'editTrackerModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return "/configuration/defecttrackers/" + tracker.id + "/edit" + $scope.csrfToken;
                },
                object: function() {
                    return tracker;
                },
                buttonText: function() {
                    return "Save Edits";
                },
                config: function() {
                    return {
                        trackerTypes: $scope.defectTrackerTypes
                    };
                },
                deleteUrl: function() {
                    return "/configuration/defecttrackers/" + tracker.id + "/delete" + $scope.csrfToken;
                }
            }
        });

        modalInstance.result.then(function (editedTracker) {

            $scope.trackers.sort(nameCompare);

            $scope.successMessage = "Successfully edited tracker " + editedTracker.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

});