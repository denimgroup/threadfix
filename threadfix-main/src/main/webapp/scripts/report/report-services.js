var threadfixModule = angular.module('threadfix')

threadfixModule.factory('reportExporter', function() {

    var reportExporter = {};

    reportExporter.exportCSV = function() {
    };

    reportExporter.exportPDF = function(d3, width, height, name) {
        var svg = d3.select("svg");
        reportExporter.exportPDFSvg(d3, svg, width, height, name);
    }

    reportExporter.exportPDFSvg = function(d3, svg, width, height, name) {
        var node = svg
            .attr("version", 1.1)
            .attr("xmlns", "http://www.w3.org/2000/svg")
            .node();

        styles(node);

        var html = node.parentNode.innerHTML;

        var imgsrc = 'data:image/svg+xml;base64,'+ btoa(html);
        var img = '<img src="'+imgsrc+'">';
        d3.select("#svgdataurl").html(img);

        var canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        var context = canvas.getContext("2d");

        var image = new Image();
        image.src = imgsrc;
        image.onload = function() {
            context.drawImage(image, 0, 0);

            var canvasdata = canvas.toDataURL("image/png");

            var pngimg = '<img src="'+canvasdata+'">';
            d3.select("#pngdataurl").html(pngimg);

            var a = document.createElement("a");
            a.download = name + ".png";
            a.href = canvasdata;
            a.click();
        };

    };

    var styles = function(dom) {
        var used = "";
        var sheets = document.styleSheets;
        for (var i = 0; i < sheets.length; i++) {
            var rules = sheets[i].cssRules;
            for (var j = 0; j < rules.length; j++) {
                var rule = rules[j];
                if (typeof(rule.style) != "undefined") {
                    try {
                        var elems = dom.querySelectorAll(rule.selectorText);
                        if (elems.length > 0) {
                            used += rule.selectorText + " { " + rule.style.cssText + " }\n";
                        }
                    } catch (x) {
                        console.log(x);
                    }
                }
            }
        };

        var s = document.createElement('style');
        s.setAttribute('type', 'text/css');
        s.innerHTML = "<![CDATA[\n" + used + "\n]]>";

        var defs = document.createElement('defs');
        defs.appendChild(s);
        dom.insertBefore(defs, dom.firstChild);
    };

    return reportExporter;
});

threadfixModule.factory('d3Service', function() {

    var d3Service = {};

    d3Service.getColorScale = function(d3, range) {
        return d3.scale.ordinal()
            .range(range);
    }

    d3Service.getScaleOrdinalRangeBand = function(d3, range, scale) {
        return d3.scale.ordinal()
            .rangeRoundBands(range, scale);
    }

    d3Service.getScaleLinearRange = function(d3, range) {
        return d3.scale.linear()
            .rangeRound(range);
    }

    d3Service.getAxis = function(d3, scale, orient) {
        return  d3.svg.axis()
            .scale(scale)
            .tickSize(3)
            .orient(orient);
    };

    d3Service.getAxisFormat = function(d3, scale, orient, format) {
        return  d3Service.getAxis(d3, scale, orient)
            .tickFormat(format);
    };

    d3Service.getSvg = function(d3, elementId, w, h) {
        return d3.select(elementId).append("svg")
            .attr("width", w)
            .attr("height", h);
    }

    d3Service.getExistingSvg = function(d3, elementId, w, h) {
        var svgs = d3.select(elementId).selectAll("svg");
        if (svgs.length>0 && svgs[0].length>0)
            return svgs;
        return d3.select(elementId).append("svg")
            .attr("width", w)
            .attr("height", h);
    }

    d3Service.getTip = function(d3, clazz, offset, tipId) {
        return d3.tip()
            .attr('class', clazz)
            .attr('id', tipId)
            .offset(offset);
    }

    return d3Service;

});

threadfixModule.factory('reportConstants', function() {

    var reportConstants = {};

    reportConstants.vulnTypeColorList = ["#014B6E", "#458A37", "#EFD20A", "#F27421", "#F7280C"];
    reportConstants.vulnTypeList = ["Info", "Low", "Medium", "High", "Critical"];
    reportConstants.vulnTypeColorMap = {
        Info: reportConstants.vulnTypeColorList[0],
        Low: reportConstants.vulnTypeColorList[1],
        Medium: reportConstants.vulnTypeColorList[2],
        High: reportConstants.vulnTypeColorList[3],
        Critical: reportConstants.vulnTypeColorList[4]
    };

    return reportConstants;

});

threadfixModule.factory('reportUtilities', function(vulnSearchParameterService, threadFixModalService) {

    var reportUtilities = {};
    var drawingDuration = 500;

    reportUtilities.drawTitle = function(svg, w, label, title, y) {
        var teams, apps, tags;
        if (label) {
            teams = label.teams;
            apps = label.apps;
            tags = label.tags;
        }
        svg.append("g")
            .append("text")
            .attr("x", w/2)
            .attr("y", y)
            .attr("class", "header")
            .text(title)
        var i = 0;
        if (teams) {
            svg.append("g")
                .append("text")
                .attr("x", w/2)
                .attr("y", y + 20)
                .attr("class", "title")
                .text("Team: " + teams);
            i++;
        }
        if (apps) {
            svg.append("g")
                .append("text")
                .attr("x", w/2)
                .attr("y", y + 20 + i*15)
                .attr("class", "title")
                .text("Application: " + apps);
            i++;
        }
        if (tags) {
            svg.append("g")
                .append("text")
                .attr("x", w/2)
                .attr("y", y + 20 + i*15)
                .attr("class", "title")
                .text("Tags: " + tags)
        }
    }

    reportUtilities.createTeamAppNames = function($scope) {
        var teams;
        var apps;
        var tags;
        if ($scope.parameters.teams && $scope.parameters.applications)
            if ($scope.parameters.teams.length === 0
                && $scope.parameters.applications.length === 0) {
                teams = "All";
                apps = "All";
            } else {
                if ($scope.parameters.teams.length > 0) {
                    teams = $scope.parameters.teams[0].name;
                }
                var i;
                for (i=1; i<$scope.parameters.teams.length; i++) {
                    teams += ", " + $scope.parameters.teams[i].name;
                }

                if ($scope.parameters.applications.length > 0) {
                    apps = $scope.parameters.applications[0].name;
                }
                for (i=1; i<$scope.parameters.applications.length; i++) {
                    apps += ", " + $scope.parameters.applications[i].name;
                }
            }

        if ($scope.parameters.tags) {
            if ($scope.parameters.tags.length === 0) {
                tags = "All";
            } else {
                if ($scope.parameters.tags.length > 0) {
                    tags = $scope.parameters.tags[0].name;
                }
                var i;
                for (i=1; i<$scope.parameters.tags.length; i++) {
                    tags += ", " + $scope.parameters.tags[i].name;
                }
            }
        }

        if (!$scope.title)
            $scope.title = {};
        $scope.title.teams = teams;
        $scope.title.apps = apps;
        $scope.title.tags = tags;
    }

    reportUtilities.drawTable = function(d3, tableData, divId) {

        var table = d3.select("#" + divId).select("table").attr("class", "table"),
            thead = d3.select("#" + divId).select("thead"),
            tbody = d3.select("#" + divId).select("tbody");

        thead.selectAll('*').remove();
        tbody.selectAll('*').remove();


        thead.selectAll("th")
            .data(d3.keys(tableData[0]))
            .enter().append("th").text(function(d){return d});

        // First create the table rows
        var tr = tbody.selectAll("tr")
            .data(tableData).enter().append("tr");

        // Now create the table cells
        var td = tr.selectAll("td")
            .data(function(d){return d3.values(d)})
            .enter().append("td")
            .text(function(d) {return d});
    }

    return reportUtilities;

});


