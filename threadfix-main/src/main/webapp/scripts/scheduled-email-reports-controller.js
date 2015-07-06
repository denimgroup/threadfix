var module = angular.module('threadfix')

module.controller('ScheduledEmailReportsController', function($scope, $http, $modal, $log, tfEncoder, threadFixModalService){

    $scope.scheduledEmailReports = [];

    var scheduleCompare = function(a,b){
        if (a.id < b.id) return -1;
        if (a.id > b.id) return 1;
        return 0;
    };

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/scheduledEmailReports/info')).
            success(function(data, status, headers, config) {

                if (data.success) {
                    $scope.scheduledEmailReports = data.object.scheduledEmailReports;
                    $scope.genericSeverities = data.object.genericSeverities;
                    $scope.organizations = data.object.organizations;
                    $scope.isConfiguredEmail = data.object.isConfiguredEmail;
                    $scope.emailLists = data.object.emailLists;

                    if ($scope.scheduledEmailReports.length === 0) {
                        $scope.scheduledEmailReports = undefined;
                    } else {
                        $scope.scheduledEmailReports.sort(scheduleCompare);
                    }
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve scheduled reports. HTTP status was " + status;
            });
    });

    $scope.openNewModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'createScheduledReportModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/scheduledEmailReports/add");
                },
                object: function() {
                    return {
                        frequency: 'Daily',
                        hour: '6',
                        minute: '0',
                        period: 'AM',
                        day: 'Sunday'
                    };
                },
                config: function(){
                    return {
                        genericSeverities: $scope.genericSeverities,
                        organizations: $scope.organizations
                    }
                },
                buttonText: function() {
                    return "Create Scheduled Email Report";
                }
            }
        });

        modalInstance.result.then(function (newscheduledReport) {
            if (!$scope.scheduledEmailReports) {
                $scope.scheduledEmailReports = [];
            }
            $scope.scheduledEmailReports.push(newscheduledReport);
            $scope.scheduledEmailReports.sort(scheduleCompare);
            $scope.successMessage = "Successfully created scheduled email report.";
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.openEditModal = function(scheduledReport) {
        //preparing input model for the multi-select directive, a bit odd but we have to initialize the multi-select from the input-model
        var configInputModelOrgs = angular.copy($scope.organizations);
        configInputModelOrgs.forEach(function(organization){
            scheduledReport.organizations.some(function(reportOrganization){
                if (organization.id === reportOrganization.id) {
                    organization.selected = true;
                    return true;
                }
            })
        });

        var modalInstance = $modal.open({
            templateUrl: 'editScheduledReportModal.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/scheduledEmailReports/" + scheduledReport.id + "/update");
                },
                object: function() {
                    var scheduledReportCopy = angular.copy(scheduledReport);
                    return scheduledReportCopy;
                },
                config: function(){
                    return {
                        genericSeverities: $scope.genericSeverities,
                        organizations: configInputModelOrgs
                    }
                },
                buttonText: function() {
                    return "Save Edits";
                },
                deleteUrl: function() {
                    return tfEncoder.encode("/configuration/scheduledEmailReports/" + scheduledReport.id + "/delete");
                }
            }
        });

        modalInstance.result.then(function (editedScheduledReport) {

            if (editedScheduledReport) {
                threadFixModalService.deleteElement($scope.scheduledEmailReports, scheduledReport);
                threadFixModalService.addElement($scope.scheduledEmailReports, editedScheduledReport);

                $scope.successMessage = "Successfully edited Scheduled Email Report.";
                $scope.scheduledEmailReports.sort(scheduleCompare);
            } else {
                threadFixModalService.deleteElement($scope.scheduledEmailReports, scheduledReport);
                $scope.successMessage = "Scheduled Email Report was successfully deleted.";
            }

        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showEmailAddresses = function(scheduledReport){
        if ("showEmailAddresses" in scheduledReport){
            scheduledReport.showEmailAddresses = !scheduledReport.showEmailAddresses;
        }
        else {
            scheduledReport.showEmailAddresses = true;
        }
    };

    $scope.addNewEmail = function(scheduledReport){
        if (!scheduledReport.newEmailAddress) return;
        scheduledReport.newEmailError = null;
        scheduledReport.newEmailLoading = true;
        var addEmailUrl = tfEncoder.encode("/configuration/scheduledEmailReports/" + scheduledReport.id + "/addEmail");// + emailAddress);
        $http.post(addEmailUrl, {"emailAddress": scheduledReport.newEmailAddress}).
        success(function(data, status, headers, config) {
            if (data.success) {
                scheduledReport.newEmailAddress = null;
                threadFixModalService.addElement(scheduledReport.emailAddresses, data.object);
            }
            else {
                scheduledReport.newEmailError = data.message;
            }
        }).
        error(function(data, status, headers, config) {
            $scope.error = "Failure. HTTP status was " + status;
        });
        scheduledReport.newEmailLoading = false;
    };

    $scope.deleteEmailAddress = function(scheduledReport, emailAddress){
        if (confirm("Delete this email address?")) {
            scheduledReport.newEmailLoading = true;
            var deleteUrl = tfEncoder.encode("/configuration/scheduledEmailReports/" + scheduledReport.id + "/deleteEmail");// + emailAddress);
            $http.post(deleteUrl, {"emailAddress": emailAddress}).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.successMessage = "Successfully deleted email address " + emailAddress;
                    threadFixModalService.deleteElement(scheduledReport.emailAddresses, emailAddress);
                }
                else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.error = "Failure. HTTP status was " + status;
            });
            scheduledReport.newEmailLoading = false;
        }
    };

    $scope.selectedEmailList = function(scheduledReport, emailList) {
        scheduledReport.newEmailListId = emailList.id;
    };

    $scope.addNewEmailList = function(scheduledReport){
        if (!scheduledReport.newEmailList) return;
        scheduledReport.newEmailListError = null;
        scheduledReport.newEmailListLoading = true;
        var addEmailListUrl = tfEncoder.encode("/configuration/scheduledEmailReports/" + scheduledReport.id + "/addEmailList");
        $http.post(addEmailListUrl, {"emailListId": scheduledReport.newEmailList.id}).
            success(function(data, status, headers, config) {
                if (data.success) {
                    scheduledReport.newEmailList = null;
                    threadFixModalService.addElement(scheduledReport.emailLists, data.object);
                }
                else {
                    scheduledReport.newEmailListError = data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.error = "Failure. HTTP status was " + status;
            });
        scheduledReport.newEmailLoading = false;
    };

    $scope.deleteEmailList = function(scheduledReport, emailList){
        if (confirm("Delete this email list?")) {
            scheduledReport.newEmailLoading = true;
            var deleteUrl = tfEncoder.encode("/configuration/scheduledEmailReports/" + scheduledReport.id + "/deleteEmailList");
            $http.post(deleteUrl, {"emailListId": emailList.id}).
                success(function(data, status, headers, config) {
                    if (data.success) {
                        $scope.successMessage = "Successfully deleted email list " + emailList.name;
                        threadFixModalService.deleteElement(scheduledReport.emailLists, emailList);
                    }
                    else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.error = "Failure. HTTP status was " + status;
                });
            scheduledReport.newEmailLoading = false;
        }
    };
});
