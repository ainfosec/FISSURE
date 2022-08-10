//
// Copyright 2016-2019 Matt Hostetter.
//
// This is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3, or (at your option)
// any later version.
//
// This software is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this software; see the file COPYING.  If not, write to
// the Free Software Foundation, Inc., 51 Franklin Street,
// Boston, MA 02110-1301, USA.
//

var planes = {};

// Create SocketIO instance
var socket = io('http://localhost:5000');

socket.on('connect', function() {
  console.log('Client has connected via SocketIO.');
});
socket.on('disconnect', function() {
  console.log('Client disconnected via SocketIO.');
});
socket.on('updatePlane', function(plane) {
  updatePlane(map, plane);
});

// Create the leaflet map
var map = L.map('map');

// Attempt to locate user. Map will also center to first plane, once received.
map.locate({setView: true});

// Load various tiles
var OpenStreetMap_Mapnik = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
	maxZoom: 19,
	attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
});
var CartoDB_VoyagerLabelsUnder = L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager_labels_under/{z}/{x}/{y}{r}.png', {
	attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
	subdomains: 'abcd',
	maxZoom: 19
});
var CartoDB_Positron = L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
	attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
	subdomains: 'abcd',
	maxZoom: 19
});
var CartoDB_DarkMatter = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
	attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
	subdomains: 'abcd',
	maxZoom: 19
});
var Esri_WorldGrayCanvas = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
	attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
	maxZoom: 16
});
var Esri_WorldTopoMap = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}', {
	attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ, TomTom, Intermap, iPC, USGS, FAO, NPS, NRCAN, GeoBase, Kadaster NL, Ordnance Survey, Esri Japan, METI, Esri China (Hong Kong), and the GIS User Community'
});
var Esri_WorldImagery = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
	attribution: 'Tiles &copy; Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community'
});
var Stamen_TonerLite = L.tileLayer('https://stamen-tiles-{s}.a.ssl.fastly.net/toner-lite/{z}/{x}/{y}{r}.{ext}', {
	attribution: 'Map tiles by <a href="http://stamen.com">Stamen Design</a>, <a href="http://creativecommons.org/licenses/by/3.0">CC BY 3.0</a> &mdash; Map data &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
	subdomains: 'abcd',
	minZoom: 0,
	maxZoom: 20,
	ext: 'png'
});

// Set default tile set
CartoDB_VoyagerLabelsUnder.addTo(map);

// Add layer/tile control
var baseMaps = {
  'OpenStreetMaps': OpenStreetMap_Mapnik,
  'CartoDB Voyager': CartoDB_VoyagerLabelsUnder,
  'CartoDB Positron': CartoDB_Positron,
  'CartoDB Dark Matter': CartoDB_DarkMatter,
  'ESRI Gray': Esri_WorldGrayCanvas,
  'ESRI Topo': Esri_WorldTopoMap,
  'ESRI World Imagery': Esri_WorldImagery,
  'Stamen Toner Lite': Stamen_TonerLite
};
var overlayMaps = {};
L.control.layers(baseMaps, overlayMaps).addTo(map);

// Colormap of altitudes in increments of 1000 ft (Rainbow)
var colormapRainbow = [
  '#ff0000', '#ff1209', '#ff2512', '#ff3b1d', '#ff4d27', '#ff5f30', '#ff733b', '#ff8344', '#ff954e',
  '#ffa457', '#ffb260', '#f2c16a', '#e6cd73', '#d8d97c', '#cce284', '#c0ea8c', '#b2f295', '#a6f79d',
  '#98fba5', '#8cfeac', '#80feb3', '#72febb', '#66fbc1', '#58f7c8', '#4cf2ce', '#40ecd3', '#32e2d9',
  '#26d9de', '#18cde3', '#0cc1e7', '#00b4eb', '#0da4ef', '#1995f2', '#2783f5', '#3373f8', '#3f61fa',
  '#4d4dfb', '#593bfd', '#6725fe', '#7312fe', '#7f00ff'
];
colormap = colormapRainbow;

var planeIcon = L.icon({
  iconUrl: './img/airliner.png',
  iconSize:     [20, 20],
});

// // Adjust marker size based on zoom level
// var planeSize = [50, 50, 50, 50, 50, 50, 50, 40, 30, 20, 10, 10, 10, 10, 10, 10, 10, 10];

// map.on('zoomend', function() {
//   var currentZoom = map.getZoom();
//   console.log('Zooming ' + currentZoom);
//   planeIcon.iconSize = planeSize[currentZoom];
// });


function updatePlane(map, plane) {
  if (planes[plane.icao] == undefined) {
    addPlane(map, plane);
  }
  else {
    movePlane(map, plane);
  }
}


function addPlane(map, plane) {
  latlng = [plane.latitude, plane.longitude];
  // Set initial view of map on first plane reception
  if (Object.keys(planes).length == 0) {
    map.setView(latlng, 9);
  }
  planes[plane.icao] = {};
  planes[plane.icao]['marker'] = L.marker(latlng, {
    icon: planeIcon,
    rotationAngle: headingToRotationAngle(plane.heading),
    rotationOrigin: 'center center'
  }).addTo(map);
  planes[plane.icao]['tooltip'] = L.tooltip(formatTooltip(plane));
  planes[plane.icao]['popup'] = L.popup(formatPopup(plane));
  planes[plane.icao]['marker'].bindTooltip(planes[plane.icao]['tooltip']);
  planes[plane.icao]['marker'].bindPopup(planes[plane.icao]['popup']);
  planes[plane.icao]['track'] = L.layerGroup();
  planes[plane.icao]['last_location'] = latlng;
}


function movePlane(map, plane) {
  latlng = [plane.latitude, plane.longitude];
  planes[plane.icao]['marker'].setLatLng(latlng);
  planes[plane.icao]['marker'].setRotationAngle(headingToRotationAngle(plane.heading));
  planes[plane.icao]['tooltip'].setContent(formatTooltip(plane));
  planes[plane.icao]['popup'].setContent(formatPopup(plane));
  prev_latlng = planes[plane.icao]['last_location']
  planes[plane.icao]['track'].addLayer(L.polyline([prev_latlng, latlng], {color: altitudeColor(plane.altitude)}).addTo(map));
  planes[plane.icao]['last_location'] = latlng;
}


function formatTooltip(plane) {
  return plane.icao + ': ' + plane.callsign;
}


function formatPopup(plane) {
  str = '<table>';
  str += '<tr><td><b>ICAO</b></td><td>' + plane.icao + '</td></tr>';
  str += '<tr><td><b>Callsign</b></td><td><a href=\"http://flightaware.com/live/flight/' + plane.callsign + '\" target=\"_blank\">' + plane.callsign + '</a></td></tr>';
  str += '<tr><td><b>Datetime</b></td><td>' + plane.datetime + '</td></tr>';
  str += '<tr><td><b>Altitude</b></td><td>' + plane.altitude + ' ft</td></tr>';
  str += '<tr><td><b>Vertical Rate</b></td><td>' + plane.vertical_rate + ' ft/min</td></tr>';
  str += '<tr><td><b>Speed</b></td><td>' + plane.speed.toFixed(0) + ' kt</td></tr>';
  str += '<tr><td><b>Heading</b></td><td>' + plane.heading.toFixed(0) + ' deg</td></tr>';
  str += '<tr><td><b>Latitude</b></td><td>' + plane.latitude.toFixed(8) + '</td></tr>';
  str += '<tr><td><b>Longitude</b></td><td>' + plane.longitude.toFixed(8) + '</td></tr>';
  str += "</table>"

  return str;
}


function headingToRotationAngle(heading) {
  return -heading;
}


function altitudeColor(altitude) {
  if (altitude != undefined && altitude != -1) {
    idx = Math.floor(altitude / 1000);
    if (idx < 0) {
      idx = 0;
    }
    else if (idx >= colormap.length) {
      idx = colormap.length - 1;
    }
    return colormap[idx];
  }
  else {
    return 'black';
  }
}
