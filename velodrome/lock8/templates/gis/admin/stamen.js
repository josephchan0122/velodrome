{% extends "gis/admin/openlayers.js" %}

{% block base_layer %}new OpenLayers.Layer.OSM("OpenStreetMap (Mapnik)", [
    "https://a.tile.openstreetmap.org/${z}/${x}/${y}.png",
    "https://b.tile.openstreetmap.org/${z}/${x}/${y}.png",
    "https://c.tile.openstreetmap.org/${z}/${x}/${y}.png"]);{% endblock %}

{% block map_creation %}
{{ block.super }}
function addStamenLayer(name) {
  window.stamen.tile.providers[name].url = "https://stamen-tiles.a.ssl.fastly.net/" + name + "/{Z}/{X}/{Y}.png";
  var stamen_layer = new OpenLayers.Layer.Stamen(name);
  {{ module }}.map.addLayer(stamen_layer);
}
addStamenLayer('terrain');
addStamenLayer('toner-lite');
{% endblock %}
