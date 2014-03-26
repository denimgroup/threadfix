var module = angular.module('threadfix')

module.controller('DefectTrackersController', function($scope, $http, $modal, $log, tfEncoder) {

    $scope.trackers = [];

    $scope.loading = true;

    $scope.empty = true;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/defecttrackers/info')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.trackers = data.object.defectTrackers;

                    $scope.empty = $scope.trackers.length === 0;

                    $scope.defectTrackerTypes = data.object.defectTrackerTypes;

                    $scope.trackers.sort(nameCompare);
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newTrackerModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/defecttrackers/new");
                },
                object: function() {
                    return {
                        defectTrackerType: $scope.defectTrackerTypes[0]
                    };
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

            $scope.trackers.push(newTracker);

            $scope.empty = $scope.trackers.length === 0;

            $scope.trackers.sort(nameCompare);

            $scope.successMessage = "Successfully created key " + newTracker.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

    $scope.openEditModal = function(tracker) {
        var modalInstance = $modal.open({
            templateUrl: 'editTrackerModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/defecttrackers/" + tracker.id + "/edit");
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
                    return tfEncoder.encode("/configuration/defecttrackers/" + tracker.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedTracker) {

            if (editedTracker) {
                $scope.trackers.sort(nameCompare);
            } else {
                var index = $scope.trackers.indexOf(tracker);

                if (index > -1) {
                    $scope.trackers.splice(index, 1);
                }

                $scope.empty = $scope.trackers.length === 0;
            }

            $scope.successMessage = "Successfully edited tracker " + editedTracker.name;

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    }

});