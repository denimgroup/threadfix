var module = angular.module('threadfix');

module.controller('VulnSearchController', function($scope, $http, tfEncoder) {
    $scope.parameters = {
        teams: [{}],
        applications: [{}],
        scanners: [{}],
        genericVulnerabilities: [{}],
        severities: [],
        numberVulnerabilities: 10,
        showOpen: true,
        showClosed: false,
        showFalsePositive: false,
        showHidden: false
    };

    $scope.$watch(function() { return $scope.parameters; }, $scope.refresh, true);

    // glue code to make angular and spring play nice
    var updateParameters = function() {
        $scope.parameters.genericSeverities = [];
        if ($scope.parameters.severities.info) {
            $scope.parameters.genericSeverities.push({ intValue: 1 });
        }
        if ($scope.parameters.severities.low) {
            $scope.parameters.genericSeverities.push({ intValue: 2 });
        }
        if ($scope.parameters.severities.medium) {
            $scope.parameters.genericSeverities.push({ intValue: 3 });
        }
        if ($scope.parameters.severities.high) {
            $scope.parameters.genericSeverities.push({ intValue: 4 });
        }
        if ($scope.parameters.severities.critical) {
            $scope.parameters.genericSeverities.push({ intValue: 5 });
        }

        $scope.parameters.teams.forEach(function(filteredTeam) {
            filteredTeam.id = undefined;
        });
        $scope.teams.forEach(function(team) {
            $scope.parameters.teams.forEach(function(filteredTeam) {
                if (team.name === filteredTeam.name) {
                    filteredTeam.id = team.id;
                }
            });
        });

        // This may be a problem down the road, but it's easier than fighting angular / bootstrap typeahead
        $scope.parameters.applications.forEach(function(filteredApp) {
            filteredApp.id = undefined;
        });
        $scope.applications.forEach(function(app) {
            $scope.parameters.applications.forEach(function(filteredApp) {
                if (filteredApp.name === (app.team.name + " / " + app.name)) {
                    filteredApp.id = app.id;
                }
            });
        });

        $scope.parameters.channelTypes = $scope.parameters.scanners;

        $scope.parameters.channelTypes.forEach(function(filteredScanner) {
            filteredScanner.id = undefined;
        });
        $scope.scanners.forEach(function(scanner) {
            $scope.parameters.channelTypes.forEach(function(filteredScanner) {
                if (scanner.name === filteredScanner.name) {
                    filteredScanner.id = scanner.id;
                }
            });
        });

        var numberRegex = /^([0-9]+)$/;
        var autocompleteRegex = /.* ([0-9]+)\)$/;

        $scope.parameters.genericVulnerabilities.forEach(function(genericVulnerability) {
            if (numberRegex.test(genericVulnerability.text)) {
                genericVulnerability.id = numberRegex;
            } else if (autocompleteRegex.test(genericVulnerability.text)) {
                var matches = autocompleteRegex.exec(genericVulnerability.text);
                genericVulnerability.id = matches[1];
            } else {
                genericVulnerability.id = undefined;
            }
        });

        $scope.parameters.endDate = undefined;
        $scope.parameters.startDate = undefined;

        var date;

        if ($scope.endDate) {
            date = new Date($scope.endDate);
            if (date) {
                $scope.parameters.endDate = date.getTime();
            }
        }
        if ($scope.startDate) {
            date = new Date($scope.startDate)
            if (date) {
                $scope.parameters.startDate = date.getTime();
            }
        }

    }

    $scope.maxDate = new Date();

    $scope.openEndDate = function($event) {
        $event.preventDefault();
        $event.stopPropagation();

        $scope.endDateOpened = true;
    };

    $scope.openStartDate = function($event) {
        $event.preventDefault();
        $event.stopPropagation();

        $scope.startDateOpened = true;
    };

    $scope.refresh = function() {
        $scope.loading = true;
        updateParameters();
        $http.post(tfEncoder.encode("/reports/search"), $scope.parameters).
            success(function(data, status, headers, config) {
                $scope.initialized = true;

                if (data.success) {
                    $scope.vulns = data.object;
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.loading = false;
            }).
            error(function(data, status, headers, config) {
                $scope.errorMessage = "Failed to retrieve team list. HTTP status was " + status;
                $scope.loading = false;
            });
    }

    $scope.add = function(collection) {
        collection.push({ name: '' })
    }

    $scope.remove = function(collection, index) {
        collection.splice(index, 1);
        $scope.refresh();
    }

    $scope.setNumberVulnerabilities = function(number) {
        $scope.parameters.numberVulnerabilities = number;
        $scope.refresh();
    }

    $scope.setDaysOldModifier = function(modifier) {
        if ($scope.parameters.daysOldModifier === modifier) {
            $scope.parameters.daysOldModifier = undefined;
            $scope.refresh();
        } else {
            $scope.parameters.daysOldModifier = modifier;
            if ($scope.parameters.daysOld) {
                $scope.refresh();
            }
        }
    }

    $scope.setDaysOld = function(days) {
        if ($scope.parameters.daysOld === days) {
            $scope.parameters.daysOld = undefined;
            $scope.refresh();
        } else {
            $scope.parameters.daysOld = days;
            if ($scope.parameters.daysOldModifier) {
                $scope.refresh();
            }
        }
    }

    $scope.setNumberMerged = function(numberMerged) {
        if ($scope.parameters.numberMerged === numberMerged) {
            $scope.parameters.numberMerged = undefined;
            $scope.refresh();
        } else {
            $scope.parameters.numberMerged = numberMerged;
            $scope.refresh();
        }
    }

});
