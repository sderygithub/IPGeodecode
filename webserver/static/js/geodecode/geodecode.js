
var s;
var svg;
var node;
var graph;
var isRunning = true;
var isCommunityView = true;
var activeColormap = 1;
var activeSize = 1;

function getParameterByName(name) {
  name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
  var regex = new RegExp("[\\?&]" + name + "=([^&#]*)")
  var results = regex.exec(location.search);
  return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

function geodecodeIP(callback) {
  search = document.getElementById('input_search_id').value.trim()
  HoldOn.open({
    theme: 'sk-cube-grid',
    message: '<h3>Geodecoding ...</h3><br><h4>Thank you for your patience</h4>'
  });
  request = '/geodecode/?ipaddress=' + search
  sendXMLHttpRequest(request,callback)
}

function updateSearchResult(json) {
  data = JSON.parse(json);
  console.log(data)
  $('#table_body_id').html("")
  if (data != undefined) {
    data.forEach(function (d) {
      $('#table_body_id').append("<tr><td>" + d['address'] + "</td><td>" + d['city'] + "</td><td>" + d['organization'] + "</td><td>" + d['longitude'].toString() + "</td><td>" + d['latitude'].toString() + "</td></tr>")
    })
  }

}

function sendXMLHttpRequest(request,callback) {
  var xobj = new XMLHttpRequest();
  xobj.overrideMimeType("application/json");
  xobj.open('GET', request, true);
  xobj.onreadystatechange = function () {
    if ( (xobj.status >= 200 && xobj.status < 300 || xobj.status === 304 ) ) {
      callback(xobj.responseText);
      HoldOn.close();
    }
    else {
      HoldOn.open({
        theme: 'sk-cube-grid',
        message: '<h3>An error occured during search</h3><br><h4>Sorry for any inconvenience and thank you for understanding</h4>',
        textColor: "red"
      });
      setTimeout(function() {
        HoldOn.close();
      },2000)
    }
  };
  xobj.send(null);
}


var width = document.width;
var height = document.height;

function redraw() {
  if (d3.event != null) {
    svg.attr("transform",
          "translate(" + d3.event.translate + ")"
        + " scale(" + d3.event.scale + ")");
  }
}


function updateScale(node_property) {
  min = 99999;
  max = -99999;
  property_value = 0;
  graph.nodes.forEach(function(d) {
    property_value = activeProperty(d,node_property)
    if (property_value < min) min = property_value
    if (property_value > max) max = property_value
  })
  jetColorScale = d3.scale.linear()
    .domain([min,min+(max-min)*0.2,min+(max-min)*0.4,min+(max-min)*0.6,min+(max-min)*0.8,max])
    .range(["#00008F","#0000FF","#00FFFF","#FFFF00","#FF0000","#800000"]);
  sizeScale = d3.scale.linear()
    .domain([min,max])
    .range([5,30])
}



