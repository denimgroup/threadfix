var module = angular.module('threadfix');

module.controller('VulnSearchController', function($scope, $http, tfEncoder) {
    $scope.parameters = {
        teams: [{}],
        scanners: [{}],
        genericVulnerabilities: [{}],
        severities: [],
        numberVulnerabilities: 10
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

        // This may be a problem down the road, but it's easier than fighting angular / bootstrap typeahead
        $scope.teams.forEach(function(team) {
            $scope.parameters.teams.forEach(function(filteredTeam) {
                if (team.name === filteredTeam.name) {
                    filteredTeam.id = team.id;
                }
            });
        });

        $scope.parameters.channelTypes = $scope.parameters.scanners;

        // This may be a problem down the road, but it's easier than fighting angular / bootstrap typeahead
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
            }
        });
    }

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

});
