var filtersModule = angular.module('threadfixFilters', []);

filtersModule.filter('shortCweNames', function() {
    var akaRegex = /.*\(aka (.*)\)/;
    var parensRegex = /.*\('(.*)'\)/;
    return function(input) {
        var test1 = akaRegex.exec(input);

        if (test1) {
            return test1[1];
        }

        var test2 = parensRegex.exec(input);

        if (test2) {
            return test2[1];
        }

        return input;
    }
});

filtersModule.filter('removeSpace', function() {
    return function(input) {
        if (input) {
            return input.replace(/ /g, '');
        }
    }
});

filtersModule.filter('removeNonWord', function() {
    return function(input) {
        if (input) {
            return input.replace(/\W/g, '');
        }
    }
});

filtersModule.filter('removeEmailDomain', function() {
    return function(input) {
        if (input) {
            return input.substring(0, input.indexOf("@"));
        }
    }
});

filtersModule.filter('pivotForID', function() {
    var akaRegex = /.*\(aka (.*)\)/;
    var parensRegex = /.*\('(.*)'\)/;
    return function(input) {
        var test1 = akaRegex.exec(input);

        if (test1) {
            return test1[1].replace(/\W/g, '');
        }

        var test2 = parensRegex.exec(input);

        if (test2) {
            return test2[1].replace(/\W/g, '');
        }

        if (input) {
            return input.replace(/\W/g, '');
        }

        return input;
    }
});

