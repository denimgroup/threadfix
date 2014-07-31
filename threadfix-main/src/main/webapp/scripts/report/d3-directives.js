var d3ThreadfixModule = angular.module('d3threadfix', ['d3', 'd3donut']);

// Months Summary report
d3ThreadfixModule.directive('d3Vbars', ['$window', '$timeout', 'd3',
    function($window, $timeout, d3) {
        return {
            restrict: 'EA',
            scope: {
                data: '='
            }
            ,
            link: function(scope, ele, attrs) {
                var margin = {top: 20, right: 20, bottom: 30, left: 40},
                    width = 422 - margin.left - margin.right,
                    height = 250 - margin.top - margin.bottom;

                var x = getScaleOrdinalRangeBand(d3, [0, width], .1);

                var y = getScaleLinearRange(d3, [height, 0]);

                var color = getScaleOrdinalRange(d3, vulnTypeColorList);

                var xAxis = getAxis(d3, x, "bottom");

                var yAxis = getAxisFormat(d3, y, "left", d3.format(".2s"));

                var svg = getSvg(d3, ele[0], width + margin.left + margin.right, height + margin.top + margin.bottom)
                    .append("g")
                    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

                var tip = getTip(d3, 'd3-tip', [-10, 0])
                    .html(function(d) {
                        return "<strong>" + d.tip + ":</strong> <span style='color:red'>" + (d.y1 - d.y0) + "</span>";
                    });
                svg.call(tip);

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);
                    svg.selectAll('*').remove();

                    if (!data || data.length < 1) return;

                    barGraphData(d3, data, color);

                    x.domain(data.map(function(d) { return d.title; }));
                    y.domain([0, d3.max(data, function(d) { return d.total; })]);

                    svg.append("g")
                        .attr("class", "x axis")
                        .attr("transform", "translate(0," + height + ")")
                        .call(xAxis);

                    svg.append("g")
                        .attr("class", "y axis")
                        .call(yAxis)
                        .append("text")
                        .attr("transform", "rotate(-90)")
                        .attr("y", 6)
                        .attr("dy", ".71em")
                        .style("text-anchor", "end");

                    var col = svg.selectAll(".title")
                        .data(data)
                        .enter().append("g")
                        .attr("class", "g")
                        .attr("transform", function(d) { return "translate(" + x(d.title) + ",0)"; });

                    var drawTime = -1;
                    var numberOfCol = data.length;
                    var duration = 500/numberOfCol;
                    col.selectAll("rect")
                        .data(function(d) { return d.vulns; })
                        .enter().append("rect")
                        .attr("class", "bar")
                        .attr("width", 0)
                        .attr("y", function(d) { return y(d.y1); })
                        .attr("height", function(d) { return y(d.y0) - y(d.y1); })
                        .style("fill", function(d) { return color(d.fillColor); })
                        .on('mouseover', tip.show)
                        .on('mouseout', tip.hide)
                        .transition()
                        .attr("width", x.rangeBand())
                        .duration(duration)
                        .delay(function(d) {
                            if (d.y0 === 0)
                                drawTime++;
                            return duration*drawTime; }) ;
                };
                ;
            }
        }
    }]);


// Top Applications Summary report
d3ThreadfixModule.directive('d3Hbars', ['$window', '$timeout', 'd3',
    function($window, $timeout, d3) {
        return {
            restrict: 'EA',
            scope: {
                data: '='
            }
            ,
            link: function(scope, ele, attrs) {
                var margin = {top: 20, right: 20, bottom: 30, left: 40},
                    width = 422 - margin.left - margin.right,
                    height = 250 - margin.top - margin.bottom;

                var x = getScaleLinearRange(d3, [0, width]);

                var y = getScaleOrdinalRangeBand(d3, [0, height], .1);

                var color = getScaleOrdinalRange(d3, vulnTypeColorList);

                var xAxis = getAxis(d3, x, "bottom");

                var yAxis = getAxis(d3, y, "left");

                var svg = getSvg(d3, ele[0], width + margin.left + margin.right, height + margin.top + margin.bottom)
                    .append("g")
                    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

                var tip = getTip(d3, 'd3-tip', [-10, 0])
                    .html(function(d) {
                        return "<strong>" + d.tip + ":</strong> <span style='color:red'>" + (d.y1 - d.y0) + "</span>";
                    });
                svg.call(tip);

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);
                    svg.selectAll('*').remove();

                    if (!data || data.length < 1) return;

                    barGraphData(d3, data, color);

                    y.domain(data.map(function(d) { return d.title; }));
                    x.domain([0, d3.max(data, function(d) { return d.total; })]);

                    svg.append("g")
                        .attr("class", "y axis")
                        .attr("transform", "translate(0," + height + ")")
                        .call(xAxis);

                    svg.append("g")
                        .attr("class", "x axis")
                        .call(yAxis)
                        .append("text")
                        .attr("transform", "rotate(-90)")
                        .attr("y", 6)
                        .attr("dy", ".71em")
                        .style("text-anchor", "end");

                    var col = svg.selectAll(".title")
                        .data(data)
                        .enter().append("g")
                        .attr("class", "g")
                        .attr("transform", function(d) { return "translate(0," + y(d.title) + ")"; });

                    var drawTime = -1;
                    var numberOfRow = data.length;
                    var duration = 500/numberOfRow;

                    col.selectAll("rect")
                        .data(function(d) { return d.vulns; })
                        .enter().append("rect")
                        .attr("class", "bar")
                        .attr("height", 0)
                        .attr("x", function(d) { return x(d.y0); })
                        .attr("width", function(d) { return x(d.y1) - x(d.y0); })
                        .style("fill", function(d) { return color(d.fillColor); })
                        .on('mouseover', tip.show)
                        .on('mouseout', tip.hide)
                        .transition()
                        .attr("height", y.rangeBand())
                        .duration(duration)
                        .delay(function(d) {
                            if (d.y0 === 0)
                                drawTime++;
                            return duration*drawTime; })
                    ;
                };
                ;
            }
        }
    }]);

// Donut
d3ThreadfixModule.directive('d3Donut', ['$window', '$timeout', 'd3', 'd3donut',
    function($window, $timeout, d3, d3donut) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: "@"
            }
            ,
            link: function(scope, ele, attrs) {

                var color = getScaleOrdinalRange(d3, vulnTypeColorList);

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);

                    if (!data)
                        return;

                    color.domain(vulnTypeList);

                    var pieDim ={w:260, h: 200};

                    var svg = getSvg(d3, ele[0], pieDim.w, pieDim.h)
                        .attr("transform", "translate("+pieDim.w/2+","+pieDim.h/2+")");

                    svg.append("g").attr("id",scope.label);

                    d3donut.draw(scope.label, getData(), 135, 90, 85, 55, 30, 0.4);

                    function getData(){
                        var d = data[0];
                        return color.domain().map(function(vulnType) {
                            return {label:vulnType, value:d[vulnType], color:color(vulnType)};});
                    }

                };
                ;
            }
        }
    }]);


/*** UTILITY FUNCTIONS ***/

function getScaleOrdinalRange(d3, range) {
    return d3.scale.ordinal()
        .range(range);
}

function getScaleOrdinalRangeBand(d3, range, scale) {
    return d3.scale.ordinal()
        .rangeRoundBands(range, scale);
}

function getScaleLinearRange(d3, range) {
    return d3.scale.linear()
        .rangeRound(range);
}

function getAxis(d3, scale, orient) {
    return  d3.svg.axis()
        .scale(scale)
        .orient(orient);
};

function getAxisFormat(d3, scale, orient, format) {
    return  getAxis(d3, scale, orient)
        .tickFormat(format);
};

function getSvg(d3, elementId, w, h) {
    return d3.select(elementId).append("svg")
        .attr("width", w)
        .attr("height", h);
}

function getTip(d3, clazz, offset) {
    return d3.tip()
        .attr('class', clazz)
        .offset(offset);
}

function barGraphData(d3, data, color) {
    var keys = d3.keys(data[0]).filter(function(key) { return key; });
//    keys.sort(function(a, b) { return a.localeCompare(b); });
//
//    color.domain(keys);

    var topVulnsReport = false;

    if (keys.indexOf("count") > -1) {
//        color = getScaleOrdinalRange(d3, topVulnColor);;
        color.domain(topVulnMapKeyword);
        topVulnsReport = true;
    }
    else
        color.domain(vulnTypeList);

    data.forEach(function(d) {
        var y0 = 0;
        d.vulns = color.domain().map(function(key) {
            var _key = (topVulnsReport) ? "High" : key;
            var tip = (topVulnsReport) ? d.title + " " + d.name : key;
            return {
                fillColor: _key,
                tip : tip,
                y0: y0,
                y1: y0 += +d[key]
            };
        });
        d.total = d.vulns[d.vulns.length - 1].y1;
    });
}

var vulnTypeColorList = ["#014B6E", "#458A37", "#EFD20A", "#F27421", "#F7280C"];
var vulnTypeList = ["Info", "Low", "Medium", "High", "Critical"];
var topVulnColor = ["#6b486b"];
var topVulnMapKeyword = ["count"];
