var myAppModule = angular.module('threadfix');

myAppModule.controller('ScheduledDefectTrackerUpdateTabController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder) {

    $scope.heading = 'Scheduled Updates';

    $scope.openNewScheduledUpdateModal = function () {
        var modalInstance = $modal.open({
            templateUrl: 'newScheduledUpdate.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/defecttrackers/scheduledUpdates/addUpdate");
                },
                buttonText: function () {
                    return "Add Scheduled Update";
                },
                heading: function () {
                    return "New Scheduled Update";
                },
                object: function () {
                    return {
                        frequency: 'Daily',
                        hour: '6',
                        minute: '0',
                        period: 'AM',
                        day: 'Sunday',
                        scheduleType: 'SELECT'
                    };
                },
                config: function () {
                    return {
                        heading: 'Defect Tracker Update'
                    }
                }
            }
        });

        modalInstance.result.then(function (scheduledUpdates) {
            $scope.scheduledUpdates = scheduledUpdates;
            addExtraZero($scope.scheduledUpdates);
            setHeader();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());

        });
    };

    $scope.deleteScheduledUpdate = function (update) {

        if (confirm('Are you sure you want to delete this scheduled update?')) {
            update.deleting = true;
            $http.post(tfEncoder.encode("/configuration/defecttrackers/scheduledUpdates/update/" + update.id + "/delete")).
                success(function(data, status, headers, config) {

                    if (data.success) {
                        var index = $scope.scheduledUpdates.indexOf(update);

                        if (index > -1) {
                            $scope.scheduledUpdates.splice(index, 1);
                        }

                        setHeader();
                        $scope.successMessage = data.object;

                    } else {
                        update.deleting = false;
                        $scope.errorMessage = data.object;
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

    $scope.$on('scheduledUpdates', function (event, scheduledUpdates) {
        $scope.scheduledUpdates = scheduledUpdates;
        addExtraZero($scope.scheduledUpdates);
        setHeader();
    });

    var addExtraZero = function (listOfUpdates) {
        listOfUpdates.forEach(function(update) {
            if (update.minute === '0' || update.minute === 0) {
                update.extraMinute = '0';
            }

            update.actualHour = (update.hour === '0' || update.hour === 0) ? '12' : update.hour;

            update.timeString = (update.day || '') + ' ' + update.actualHour + ':' + (update.extraMinute || '') + update.minute + ' ' + update.period;
            update.timeStringId = update.timeString.replace(/ /g, '_').replace(/:/g, '_');
        });
    };

    var setHeader = function () {
        if (!$scope.scheduledUpdates || !$scope.scheduledUpdates.length > 0) {
            $scope.scheduledUpdates = undefined;
            $scope.heading = "0 Scheduled Updates";
        } else {
            if ($scope.scheduledUpdates.length === 1) {
                $scope.heading = '1 Scheduled Update';
            } else {
                $scope.heading = $scope.scheduledUpdates.length + ' Scheduled Updates';
            }
        }
    };
});