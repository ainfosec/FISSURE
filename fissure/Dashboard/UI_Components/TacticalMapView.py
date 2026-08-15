"""
TacticalMapView.py

Reusable offline slippy-map component for the FISSURE Dashboard.

Expected map pack layout:
    FISSURE/map_data/<map_name>/tile_manifest.json
    FISSURE/map_data/<map_name>/tiles/<zoom>/<x>/<y>.png

The Dashboard owns CoT/message parsing. This class only owns map rendering,
coordinate conversion, markers, labels, and CE rings.
"""

import json
import math
import os

from PyQt5 import QtCore, QtGui, QtWidgets
import fissure.utils

TILE_SIZE = 256

class TacticalMarkerItem(QtWidgets.QGraphicsEllipseItem):
    def __init__(self, x, y, w, h, marker_kind, marker_id, click_callback=None):
        super().__init__(x, y, w, h)
        self.marker_kind = marker_kind
        self.marker_id = marker_id
        self.click_callback = click_callback
        self.setAcceptHoverEvents(True)
        self.setCursor(QtCore.Qt.PointingHandCursor)

    def mousePressEvent(self, event):
        if self.click_callback:
            self.click_callback(
                self.marker_kind,
                self.marker_id,
                event.scenePos(),
                event.screenPos(),
            )

        event.accept()


class TacticalMapView(QtCore.QObject):
    """Offline slippy-map renderer backed by an existing QGraphicsView."""

    def __init__(self, graphics_view, parent=None, default_map_name="demo_map_pack"):
        super().__init__(parent)

        self.graphics_view = graphics_view
        self.current_map_name = default_map_name

        self.map_pack_dir = None
        self.map_manifest_path = None
        self.map_manifest = {}
        self.map_reference_points = []
        self.map_available_zooms = []
        self.map_zoom = None

        self.map_x_min = 0
        self.map_x_max = 0
        self.map_y_min = 0
        self.map_y_max = 0

        self.scene = QtWidgets.QGraphicsScene(parent or graphics_view)
        self.graphics_view.setScene(self.scene)

        self.tile_items = []
        self.reference_items = []

        self.show_ce_rings = True

        # Persistent overlay data used to redraw after zoom/map reload
        self.node_records = {}
        self.target_records = {}
        self.alert_records = {}
        self.detection_records = {}
        self.soi_records = {}

        # Live QGraphicsItems currently on the scene
        self.node_items = {}
        self.target_items = {}
        self.alert_items = {}
        self.detection_items = {}
        self.soi_items = {}

        self.node_clicked_callback = None
        self.target_clicked_callback = None
        self.alert_clicked_callback = None
        self.detection_clicked_callback = None
        self.soi_clicked_callback = None

        self._configure_graphics_view()

    # -------------------------------------------------------------------------
    # Public setup/load methods
    # -------------------------------------------------------------------------
    @staticmethod
    def get_map_data_dir():
        """
        Returns the root folder containing Tactical map packs.
        """
        return os.path.join(fissure.utils.FISSURE_ROOT, "map_data")


    @classmethod
    def get_available_map_names(cls):
        """
        Returns map pack folder names that contain a tile_manifest.json file.
        """
        map_data_dir = cls.get_map_data_dir()

        if not os.path.isdir(map_data_dir):
            return []

        map_names = []

        for name in sorted(os.listdir(map_data_dir)):
            map_pack_dir = os.path.join(map_data_dir, name)
            manifest_path = os.path.join(map_pack_dir, "tile_manifest.json")

            if os.path.isdir(map_pack_dir) and os.path.isfile(manifest_path):
                map_names.append(name)

        return map_names


    def refresh_available_maps(self):
        """
        Returns available map pack names from FISSURE/map_data.
        """
        return self.get_available_map_names()


    def load_map(self, map_name=None, preferred_zoom=None, fit=True):
        """Load a map pack from FISSURE/map_data/<map_name>."""
        if map_name is not None:
            self.current_map_name = map_name

        self.map_pack_dir = os.path.join(fissure.utils.FISSURE_ROOT, "map_data", self.current_map_name)
        self.map_manifest_path = os.path.join(self.map_pack_dir, "tile_manifest.json")

        if not os.path.isfile(self.map_manifest_path):
            print("ERROR: tile manifest not found:", self.map_manifest_path)
            self._show_error_scene("tile_manifest.json not found", self.map_manifest_path)
            return False

        with open(self.map_manifest_path, "r", encoding="utf-8") as f:
            self.map_manifest = json.load(f)

        self.map_reference_points = self.map_manifest.get("reference_points", [])
        self.map_available_zooms = sorted(int(z) for z in self.map_manifest["zoom_levels"].keys())

        if preferred_zoom is not None and preferred_zoom in self.map_available_zooms:
            self.map_zoom = preferred_zoom
        else:
            self.map_zoom = self.map_available_zooms[0]

        center_lat, center_lon = self._initial_center_latlon()
        self.load_zoom(self.map_zoom, center_lat=center_lat, center_lon=center_lon, fit=fit)

        print("loaded tactical map:", self.current_map_name, "zoom:", self.map_zoom)
        return True

    def load_zoom(self, zoom, center_lat=None, center_lon=None, fit=False):
        """Reload the map at a different available tile zoom."""
        if zoom not in self.map_available_zooms:
            return False

        self.map_zoom = zoom
        info = self.map_manifest["zoom_levels"][str(self.map_zoom)]
        self.map_x_min = int(info["x_min"])
        self.map_x_max = int(info["x_max"])
        self.map_y_min = int(info["y_min"])
        self.map_y_max = int(info["y_max"])

        self.scene.clear()
        self.tile_items = []
        self.reference_items = []
        self.node_items = {}
        self.target_items = {}
        self.alert_items = {}
        self.detection_items = {}
        self.soi_items = {}

        self._load_tiles_for_current_zoom()
        self._add_reference_points(self.map_reference_points)
        self._replot_overlays()
        self._update_scene_rect()

        if fit:
            self.graphics_view.resetTransform()
            self.graphics_view.fitInView(self.scene.sceneRect(), QtCore.Qt.KeepAspectRatio)
        elif center_lat is not None and center_lon is not None:
            scene_x, scene_y = self.latlon_to_scene(center_lat, center_lon)
            self.graphics_view.resetTransform()
            self.graphics_view.centerOn(scene_x, scene_y)

        return True

    # -------------------------------------------------------------------------
    # Public map item API
    # -------------------------------------------------------------------------
    def add_node(self, node_id, lat, lon, label=None, active=False, status=""):
        """Add or update a node marker."""
        self.node_records[node_id] = {
            "lat": lat,
            "lon": lon,
            "label": label or str(node_id),
            "active": active,
            "status": status,
        }

        return self._add_or_update_marker(
            collection=self.node_items,
            item_id=node_id,
            lat=lat,
            lon=lon,
            label=label or str(node_id),
            color=QtGui.QColor("#25e5eb"),
            radius=10,
            z_value=10,
            marker_kind="node",
            click_callback=self._handle_marker_clicked,
            active=active,
            status=status,
        )


    def add_target(self, target_id, lat, lon, label=None, ce_m=None):
        """Add or update a target marker and optional CE ring."""
        self.target_records[target_id] = {
            "lat": lat,
            "lon": lon,
            "label": label or str(target_id),
            "ce_m": ce_m,
        }

        return self._add_or_update_marker(
            collection=self.target_items,
            item_id=target_id,
            lat=lat,
            lon=lon,
            label=label or str(target_id),
            color=QtGui.QColor("#dc2626"),
            radius=6,
            z_value=20,
            ce_m=ce_m,
            marker_kind="target",
            click_callback=self._handle_marker_clicked,
        )


    def add_alert(self, alert_id, lat, lon, label=None):
        """Add or update an alert marker."""
        self.alert_records[alert_id] = {
            "lat": lat,
            "lon": lon,
            "label": label or str(alert_id),
        }

        return self._add_or_update_marker(
            collection=self.alert_items,
            item_id=alert_id,
            lat=lat,
            lon=lon,
            label=label or str(alert_id),
            color=QtGui.QColor("#f59e0b"),
            radius=5,
            z_value=30,
            marker_kind="alert",
            click_callback=self._handle_marker_clicked,
        )


    def add_detection(self, detection_id, lat, lon, label=None):
        """Add or update a detection marker."""
        self.detection_records[detection_id] = {
            "lat": lat,
            "lon": lon,
            "label": label or str(detection_id),
        }

        return self._add_or_update_marker(
            collection=self.detection_items,
            item_id=detection_id,
            lat=lat,
            lon=lon,
            label=label or str(detection_id),
            color=QtGui.QColor("#a855f7"),
            radius=5,
            z_value=25,
            marker_kind="detection",
            click_callback=self._handle_marker_clicked,
        )

    def add_soi(self, soi_id, lat, lon, label=None):
        """Add or update a rendered SOI marker."""
        self.soi_records[soi_id] = {
            "lat": lat,
            "lon": lon,
            "label": label or str(soi_id),
        }

        return self._add_or_update_marker(
            collection=self.soi_items,
            item_id=soi_id,
            lat=lat,
            lon=lon,
            label=label or str(soi_id),
            color=QtGui.QColor("#22c55e"),
            radius=5,
            z_value=24,
            marker_kind="soi",
            click_callback=self._handle_marker_clicked,
        )

    # Remove single items
    def remove_node_pin(self, node_id):
        self._remove_marker(self.node_items, node_id)


    def remove_node(self, node_id):
        self.node_records.pop(node_id, None)
        self.remove_node_pin(node_id)


    def remove_target_pin(self, target_id):
        self._remove_marker(self.target_items, target_id)


    def remove_target(self, target_id):
        self.target_records.pop(target_id, None)
        self.remove_target_pin(target_id)


    def remove_alert_pin(self, alert_id):
        self._remove_marker(self.alert_items, alert_id)


    def remove_alert(self, alert_id):
        self.alert_records.pop(alert_id, None)
        self.remove_alert_pin(alert_id)


    def remove_detection_pin(self, detection_id):
        self._remove_marker(self.detection_items, detection_id)


    def remove_detection(self, detection_id):
        self.detection_records.pop(detection_id, None)
        self.remove_detection_pin(detection_id)


    def remove_soi_pin(self, soi_id):
        self._remove_marker(self.soi_items, soi_id)        


    def remove_soi(self, soi_id):
        self.soi_records.pop(soi_id, None)
        self.remove_soi_pin(soi_id)


    # Clear pins only
    def clear_node_pins(self):
        self._clear_collection(self.node_items)


    def clear_target_pins(self):
        self._clear_collection(self.target_items)


    def clear_alert_pins(self):
        self._clear_collection(self.alert_items)


    def clear_detection_pins(self):
        self._clear_collection(self.detection_items)


    def clear_soi_pins(self):
        self._clear_collection(self.soi_items)


    def clear_overlay_pins(self):
        self.clear_node_pins()
        self.clear_target_pins()
        self.clear_alert_pins()
        self.clear_detection_pins()
        self.clear_soi_pins()


    # Clear records and pins
    def clear_node_records(self):
        self.node_records.clear()
        self.clear_node_pins()


    def clear_target_records(self):
        self.target_records.clear()
        self.clear_target_pins()


    def clear_alert_records(self):
        self.alert_records.clear()
        self.clear_alert_pins()


    def clear_detection_records(self):
        self.detection_records.clear()
        self.clear_detection_pins()


    def clear_soi_records(self):
        self.soi_records.clear()
        self.clear_soi_pins()


    def clear_overlay_records(self):
        self.clear_node_records()
        self.clear_target_records()
        self.clear_alert_records()
        self.clear_detection_records()
        self.clear_soi_records()


    def set_show_ce_rings(self, enabled):
        self.show_ce_rings = enabled

        # Rebuild rendered overlay items from persistent records
        self.clear_node_pins()
        self.clear_target_pins()
        self.clear_alert_pins()
        self.clear_detection_pins()
        self.clear_soi_pins()

        self._replot_overlays()


    # Map navigation
    def center_on_latlon(self, lat, lon):
        scene_x, scene_y = self.latlon_to_scene(lat, lon)
        scene_x, scene_y, _ = self._clamp_scene_point(
            scene_x,
            scene_y,
            margin=0,
        )
        self.graphics_view.centerOn(scene_x, scene_y)


    def current_view_center_latlon(self):
        viewport_center = self.graphics_view.viewport().rect().center()
        scene_center = self.graphics_view.mapToScene(viewport_center)
        return self.scene_to_latlon(scene_center.x(), scene_center.y())


    def center_on_node(self, node_id):
        record = self.node_records.get(node_id)
        if not record:
            return

        self.center_on_latlon(record["lat"], record["lon"])


    # Marker callbacks
    def set_node_clicked_callback(self, callback):
        self.node_clicked_callback = callback


    def set_target_clicked_callback(self, callback):
        self.target_clicked_callback = callback


    def set_alert_clicked_callback(self, callback):
        self.alert_clicked_callback = callback


    def set_detection_clicked_callback(self, callback):
        self.detection_clicked_callback = callback


    def set_soi_clicked_callback(self, callback):
        self.soi_clicked_callback = callback

    # -------------------------------------------------------------------------
    # Coordinate conversion
    # -------------------------------------------------------------------------

    def latlon_to_world(self, lat, lon, zoom=None):
        zoom = self.map_zoom if zoom is None else zoom
        lat_rad = math.radians(lat)
        n = 2 ** zoom
        x = (lon + 180.0) / 360.0 * n * TILE_SIZE
        y = (1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * n * TILE_SIZE
        return x, y


    def latlon_to_scene(self, lat, lon):
        world_x, world_y = self.latlon_to_world(lat, lon, self.map_zoom)
        scene_x = world_x - self.map_x_min * TILE_SIZE
        scene_y = world_y - self.map_y_min * TILE_SIZE
        return scene_x, scene_y
    

    def _clamp_scene_point(self, scene_x, scene_y, margin=0.0):
        """
        Clamp a rendered point to the current downloaded map extent.

        Latitude/longitude records are not modified. The returned point is only
        used for Dashboard rendering so valid off-map overlays remain visible
        and clickable at the nearest map edge.
        """
        scene_width = (
            self.map_x_max - self.map_x_min + 1
        ) * TILE_SIZE
        scene_height = (
            self.map_y_max - self.map_y_min + 1
        ) * TILE_SIZE

        if scene_width <= 0 or scene_height <= 0:
            return scene_x, scene_y, False

        off_map = (
            scene_x < 0
            or scene_x > scene_width
            or scene_y < 0
            or scene_y > scene_height
        )

        margin = max(0.0, float(margin))

        min_x = min(margin, scene_width / 2.0)
        max_x = max(min_x, scene_width - margin)
        min_y = min(margin, scene_height / 2.0)
        max_y = max(min_y, scene_height - margin)

        clamped_x = min(
            max(scene_x, min_x),
            max_x,
        )
        clamped_y = min(
            max(scene_y, min_y),
            max_y,
        )

        return clamped_x, clamped_y, off_map
    

    def scene_to_latlon(self, scene_x, scene_y):
        world_x = scene_x + self.map_x_min * TILE_SIZE
        world_y = scene_y + self.map_y_min * TILE_SIZE

        n = 2 ** self.map_zoom
        lon = world_x / (n * TILE_SIZE) * 360.0 - 180.0
        merc_y = math.pi * (1.0 - 2.0 * world_y / (n * TILE_SIZE))
        lat = math.degrees(math.atan(math.sinh(merc_y)))
        return lat, lon


    def meters_to_scene_pixels(self, lat, meters):
        """Approximate meter radius in scene pixels at the current zoom/latitude."""
        if meters is None:
            return None

        meters_per_pixel = (
            156543.03392 * math.cos(math.radians(lat)) / float(2 ** self.map_zoom)
        )
        if meters_per_pixel <= 0:
            return None
        return meters / meters_per_pixel

    # -------------------------------------------------------------------------
    # Internal methods
    # -------------------------------------------------------------------------

    def _configure_graphics_view(self):
        self.graphics_view.setDragMode(QtWidgets.QGraphicsView.ScrollHandDrag)
        self.graphics_view.setTransformationAnchor(QtWidgets.QGraphicsView.AnchorUnderMouse)
        self.graphics_view.setResizeAnchor(QtWidgets.QGraphicsView.AnchorUnderMouse)
        self.graphics_view.setRenderHint(QtGui.QPainter.Antialiasing, True)
        self.graphics_view.setRenderHint(QtGui.QPainter.SmoothPixmapTransform, True)
        self.graphics_view.wheelEvent = self._wheel_event


    def _wheel_event(self, event):
        if not self.map_available_zooms or self.map_zoom is None:
            event.accept()
            return

        zooms = sorted(self.map_available_zooms)

        try:
            current_index = zooms.index(self.map_zoom)
        except ValueError:
            event.accept()
            return

        if event.angleDelta().y() > 0:
            new_index = min(current_index + 1, len(zooms) - 1)
        else:
            new_index = max(current_index - 1, 0)

        new_zoom = zooms[new_index]

        if new_zoom != self.map_zoom:
            center_lat, center_lon = self.current_view_center_latlon()
            self.load_zoom(
                new_zoom,
                center_lat=center_lat,
                center_lon=center_lon,
                fit=False,
            )

        event.accept()


    def _initial_center_latlon(self):
        bounds = self.map_manifest.get("bounds", {})
        if all(k in bounds for k in ("north", "south", "west", "east")):
            center_lat = (bounds["north"] + bounds["south"]) / 2.0
            center_lon = (bounds["west"] + bounds["east"]) / 2.0
            return center_lat, center_lon

        return 42.1503, -76.9517


    def _load_tiles_for_current_zoom(self):
        missing = 0
        loaded = 0
        tile_root = os.path.join(self.map_pack_dir, "tiles", str(self.map_zoom))

        print("tile_root:", tile_root)
        print("zoom:", self.map_zoom)
        print("x range:", self.map_x_min, self.map_x_max)
        print("y range:", self.map_y_min, self.map_y_max)

        for x in range(self.map_x_min, self.map_x_max + 1):
            for y in range(self.map_y_min, self.map_y_max + 1):
                scene_x = (x - self.map_x_min) * TILE_SIZE
                scene_y = (y - self.map_y_min) * TILE_SIZE

                tile_path = None

                for ext in ("png", "jpg", "jpeg"):
                    candidate = os.path.join(tile_root, str(x), f"{y}.{ext}")
                    if os.path.isfile(candidate):
                        tile_path = candidate
                        break

                if tile_path is not None:
                    pixmap = QtGui.QPixmap(tile_path)

                    if pixmap.isNull():
                        missing += 1
                        print("failed to load tile:", tile_path)
                        pixmap = self._missing_tile_pixmap(x, y)
                    else:
                        loaded += 1
                else:
                    missing += 1
                    print("missing tile:", x, y)
                    pixmap = self._missing_tile_pixmap(x, y)

                item = self.scene.addPixmap(pixmap)
                item.setPos(scene_x, scene_y)
                item.setZValue(0)
                self.tile_items.append(item)

        print("loaded tiles:", loaded)
        print("missing tiles:", missing)


    def _missing_tile_pixmap(self, x, y):
        pixmap = QtGui.QPixmap(TILE_SIZE, TILE_SIZE)
        pixmap.fill(QtGui.QColor("#f0f0f0"))
        painter = QtGui.QPainter(pixmap)
        painter.setPen(QtGui.QPen(QtGui.QColor("#999999")))
        painter.drawRect(0, 0, TILE_SIZE - 1, TILE_SIZE - 1)
        painter.drawText(20, 30, "missing")
        painter.drawText(20, 55, f"z={self.map_zoom}")
        painter.drawText(20, 80, f"x={x}")
        painter.drawText(20, 105, f"y={y}")
        painter.end()
        return pixmap


    def _add_reference_points(self, points):
        colors = {
            "Corning": QtGui.QColor("#1d4ed8"),
            "Horseheads": QtGui.QColor("#dc2626"),
            "Elmira": QtGui.QColor("#16a34a"),
        }

        for point in points:
            name = point.get("name", "Reference")
            lat = point.get("lat")
            lon = point.get("lon")
            if lat is None or lon is None:
                continue

            x, y = self.latlon_to_scene(lat, lon)
            color = colors.get(name, QtGui.QColor("#000000"))

            marker = self.scene.addEllipse(
                x - 5, y - 5, 10, 10,
                QtGui.QPen(QtCore.Qt.black),
                QtGui.QBrush(color),
            )
            marker.setZValue(2)

            label = self.scene.addText(name)
            label.setDefaultTextColor(QtGui.QColor("#111111"))
            label.setPos(x + 8, y - 18)
            label.setZValue(3)

            self.reference_items.extend([marker, label])


    def _update_scene_rect(self):
        scene_width = (self.map_x_max - self.map_x_min + 1) * TILE_SIZE
        scene_height = (self.map_y_max - self.map_y_min + 1) * TILE_SIZE
        self.scene.setSceneRect(0, 0, scene_width, scene_height)

    
    def _add_or_update_marker(
        self,
        collection,
        item_id,
        lat,
        lon,
        label,
        color,
        radius=6,
        z_value=10,
        ce_m=None,
        marker_kind=None,
        click_callback=None,
        active=False,
        status="",
    ):
        self._remove_marker(collection, item_id)

        true_x, true_y = self.latlon_to_scene(
            lat,
            lon,
        )

        x, y, off_map = self._clamp_scene_point(
            true_x,
            true_y,
            margin=radius + 2,
        )

        normalized_status = str(
            status or ""
        ).strip().lower()

        disconnected = (
            marker_kind == "node"
            and normalized_status == "disconnected"
        )

        marker = TacticalMarkerItem(
            x - radius,
            y - radius,
            radius * 2,
            radius * 2,
            marker_kind=marker_kind,
            marker_id=item_id,
            click_callback=click_callback,
        )

        if disconnected:
            marker.setPen(
                QtGui.QPen(
                    QtGui.QColor("#555555"),
                    2,
                    QtCore.Qt.DashLine,
                )
            )
            marker.setBrush(
                QtGui.QBrush(
                    QtGui.QColor("#808080")
                )
            )
        else:
            marker.setPen(
                QtGui.QPen(QtCore.Qt.black)
            )
            marker.setBrush(
                QtGui.QBrush(color)
            )

        marker.setZValue(z_value)
        self.scene.addItem(marker)

        # Label with outline for readability on OSM and satellite maps.
        font = QtGui.QFont()
        font.setBold(True)
        font.setPointSize(10)

        label_text = str(label)

        if off_map:
            label_text = f"{label_text} [off map]"

        # Measure the rendered text so off-map labels can flip direction
        # only when a map edge requires it. Normal marker spacing is preserved.
        measure_item = QtWidgets.QGraphicsTextItem(
            label_text
        )
        measure_item.setFont(font)
        label_rect = measure_item.boundingRect()

        scene_width = (
            self.map_x_max - self.map_x_min + 1
        ) * TILE_SIZE
        scene_height = (
            self.map_y_max - self.map_y_min + 1
        ) * TILE_SIZE

        hit_right_edge = (
            off_map
            and true_x > scene_width
        )
        hit_top_edge = (
            off_map
            and true_y < 0
        )

        # Preserve the original above/right spacing unless an off-map marker
        # lands on an edge that requires the label to flip.
        if hit_right_edge:
            label_x = (
                x
                - radius
                - 3
                - label_rect.width()
            )
        else:
            label_x = x + radius + 3

        label_y = y - 18

        # Final safety clamp for unusually long labels or very small map packs.
        if scene_width > 0:
            max_label_x = max(
                2.0,
                scene_width
                - label_rect.width()
                - 2.0,
            )
            label_x = min(
                max(label_x, 2.0),
                max_label_x,
            )

        if scene_height > 0:
            max_label_y = max(
                2.0,
                scene_height
                - label_rect.height()
                - 2.0,
            )
            label_y = min(
                max(label_y, 2.0),
                max_label_y,
            )

        outline_items = []
        outline_offsets = [
            (-1, 0),
            (1, 0),
            (0, -1),
            (0, 1),
            (-1, -1),
            (-1, 1),
            (1, -1),
            (1, 1),
        ]

        for dx, dy in outline_offsets:
            outline = QtWidgets.QGraphicsTextItem(
                label_text
            )
            outline.setFont(font)
            outline.setDefaultTextColor(
                QtGui.QColor(0, 0, 0, 180)
            )
            outline.setPos(
                label_x + dx,
                label_y + dy,
            )
            outline.setZValue(z_value + 1)
            self.scene.addItem(outline)
            outline_items.append(outline)

        text = QtWidgets.QGraphicsTextItem(
            label_text
        )
        text.setFont(font)
        text.setDefaultTextColor(
            QtGui.QColor("#ffffff")
        )
        text.setPos(
            label_x,
            label_y,
        )
        text.setZValue(z_value + 2)
        self.scene.addItem(text)

        items = [
            marker,
            *outline_items,
            text,
        ]

        if (
            marker_kind == "node"
            and active
            and not disconnected
        ):
            active_dot_radius = max(
                3,
                int(radius * 0.35),
            )

            active_dot = self.scene.addEllipse(
                x - active_dot_radius,
                y - active_dot_radius,
                active_dot_radius * 2,
                active_dot_radius * 2,
                QtGui.QPen(QtCore.Qt.black),
                QtGui.QBrush(QtCore.Qt.black),
            )

            active_dot.setZValue(z_value + 3)
            items.append(active_dot)

        # A CE ring is geographically meaningful only around the true target
        # position. Do not draw one around an edge-clamped surrogate position.
        if (
            self.show_ce_rings
            and not off_map
            and ce_m is not None
            and ce_m > 0
        ):
            ce_px = self.meters_to_scene_pixels(
                lat,
                ce_m,
            )

            if ce_px is not None and ce_px > 0:
                ring = self.scene.addEllipse(
                    x - ce_px,
                    y - ce_px,
                    ce_px * 2,
                    ce_px * 2,
                    QtGui.QPen(
                        QtGui.QColor("#ffffff"),
                        2,
                        QtCore.Qt.DashLine,
                    ),
                    QtGui.QBrush(
                        QtCore.Qt.transparent
                    ),
                )
                ring.setZValue(z_value - 1)
                items.append(ring)

        collection[item_id] = {
            # Preserve the authoritative location exactly as received.
            "lat": lat,
            "lon": lon,
            "label": label,
            "active": active,
            "status": status,

            # Dashboard-rendering metadata only.
            "scene_x": x,
            "scene_y": y,
            "off_map": off_map,

            "items": items,
        }

        return collection[item_id]
    
    
    def _remove_marker(self, collection, item_id):
        marker_record = collection.pop(item_id, None)
        if not marker_record:
            return

        for item in marker_record.get("items", []):
            self.scene.removeItem(item)


    def _clear_collection(self, collection):
        for item_id in list(collection.keys()):
            self._remove_marker(collection, item_id)


    def _show_error_scene(self, title, detail):
        self.scene.clear()
        self.scene.setSceneRect(0, 0, 1000, 600)

        text = self.scene.addText(f"{title}\n{detail}")
        text.setDefaultTextColor(QtGui.QColor("#111111"))
        text.setPos(20, 20)
        text.setZValue(10)


    def _replot_overlays(self):
        """Redraw persistent node/target/alert records after scene reload."""

        for node_id, record in self.node_records.items():
            self._add_or_update_marker(
                collection=self.node_items,
                item_id=node_id,
                lat=record["lat"],
                lon=record["lon"],
                label=record.get("label") or str(node_id),
                color=QtGui.QColor("#25e5eb"),
                radius=10,
                z_value=10,
                marker_kind="node",
                click_callback=self._handle_marker_clicked,
                active=record.get("active", False),
                status=record.get("status", ""),
            )

        for target_id, record in self.target_records.items():
            self._add_or_update_marker(
                collection=self.target_items,
                item_id=target_id,
                lat=record["lat"],
                lon=record["lon"],
                label=record.get("label") or str(target_id),
                color=QtGui.QColor("#dc2626"),
                radius=6,
                z_value=20,
                ce_m=record.get("ce_m"),
                marker_kind="target",
                click_callback=self._handle_marker_clicked,
            )

        for alert_id, record in self.alert_records.items():
            self._add_or_update_marker(
                collection=self.alert_items,
                item_id=alert_id,
                lat=record["lat"],
                lon=record["lon"],
                label=record.get("label") or str(alert_id),
                color=QtGui.QColor("#f59e0b"),
                radius=5,
                z_value=30,
                marker_kind="alert",
                click_callback=self._handle_marker_clicked,                
            )

        for detection_id, record in self.detection_records.items():
            self._add_or_update_marker(
                collection=self.detection_items,
                item_id=detection_id,
                lat=record["lat"],
                lon=record["lon"],
                label=record.get("label") or str(detection_id),
                color=QtGui.QColor("#a855f7"),
                radius=5,
                z_value=25,
                marker_kind="detection",
                click_callback=self._handle_marker_clicked,
            )

        for soi_id, record in self.soi_records.items():
            self._add_or_update_marker(
                collection=self.soi_items,
                item_id=soi_id,
                lat=record["lat"],
                lon=record["lon"],
                label=record.get("label") or str(soi_id),
                color=QtGui.QColor("#22c55e"),
                radius=5,
                z_value=24,
                marker_kind="soi",
                click_callback=self._handle_marker_clicked,
            )


    def _handle_marker_clicked(self, marker_kind, marker_id, scene_pos=None, screen_pos=None):
        if scene_pos is not None:
            nearby = self._find_markers_near_scene_pos(scene_pos, pixel_radius=12)

            if len(nearby) > 1 and screen_pos is not None:
                self._show_marker_group_menu(nearby, screen_pos)
                return

        self._dispatch_marker_click(marker_kind, marker_id)


    def _dispatch_marker_click(self, marker_kind, marker_id):
        if marker_kind == "node" and self.node_clicked_callback:
            self.node_clicked_callback(marker_id)
        elif marker_kind == "target" and self.target_clicked_callback:
            self.target_clicked_callback(marker_id)
        elif marker_kind == "alert" and self.alert_clicked_callback:
            self.alert_clicked_callback(marker_id)
        elif marker_kind == "detection" and self.detection_clicked_callback:
            self.detection_clicked_callback(marker_id)
        elif marker_kind == "soi" and self.soi_clicked_callback:
            self.soi_clicked_callback(marker_id)


    def _find_markers_near_scene_pos(self, scene_pos, pixel_radius=12):
        if scene_pos is None:
            return []

        matches = []

        for marker_kind, collection in [
            ("node", self.node_items),
            ("target", self.target_items),
            ("alert", self.alert_items),
            ("detection", self.detection_items),
            ("soi", self.soi_items),
        ]:
            for marker_id, record in collection.items():
                x = record.get("scene_x")
                y = record.get("scene_y")

                if x is None or y is None:
                    lat = record.get("lat")
                    lon = record.get("lon")

                    if lat is None or lon is None:
                        continue

                    x, y = self.latlon_to_scene(
                        lat,
                        lon,
                    )

                distance = math.hypot(
                    scene_pos.x() - x,
                    scene_pos.y() - y,
                )

                if distance <= pixel_radius:
                    matches.append(
                        (
                            marker_kind,
                            marker_id,
                            record,
                        )
                    )

        return matches


    def _show_marker_group_menu(self, nearby, screen_pos):
        menu = QtWidgets.QMenu()

        for marker_kind, marker_id, record in nearby:
            label = record.get("label") or str(marker_id)

            if marker_kind == "node":
                status = str(record.get("status") or "unknown").strip()
                menu_text = f"Node: {label} [{status}]"
            else:
                menu_text = f"{marker_kind.title()}: {label}"

            action = menu.addAction(menu_text)
            action.setData((marker_kind, marker_id))

        selected_action = menu.exec_(screen_pos)

        if selected_action is None:
            return

        marker_kind, marker_id = selected_action.data()
        self._dispatch_marker_click(marker_kind, marker_id)