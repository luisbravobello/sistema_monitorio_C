"""
icons.py — Íconos vectoriales dibujados con QPainter.
No usa emojis ni archivos externos (.png/.svg): todo se dibuja en memoria,
así que no hay que gestionar assets ni rutas. Estilo coherente con el
splash (verde #00c853 sobre fondo oscuro).

Colocar este archivo en la misma carpeta que main.py / main_window.py (UI/).
"""

from PySide6.QtCore import Qt, QRectF, QPointF
from PySide6.QtGui import QIcon, QPixmap, QPainter, QPen, QColor, QPolygonF, QPainterPath


def _canvas(size):
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    return pm, p


def icon_app(size=64, color="#00c853", bg="#0d1f0d"):
    """Escudo con check — ícono principal de la app (título de ventana, taskbar)."""
    pm, p = _canvas(size)
    w = h = size
    p.setPen(QPen(QColor(color), max(2, size * 0.045)))
    p.setBrush(QColor(bg))
    path = QPainterPath()
    path.moveTo(w * 0.50, h * 0.05)
    path.lineTo(w * 0.88, h * 0.20)
    path.lineTo(w * 0.88, h * 0.52)
    path.cubicTo(w * 0.88, h * 0.78, w * 0.70, h * 0.92, w * 0.50, h * 0.97)
    path.cubicTo(w * 0.30, h * 0.92, w * 0.12, h * 0.78, w * 0.12, h * 0.52)
    path.lineTo(w * 0.12, h * 0.20)
    path.closeSubpath()
    p.drawPath(path)

    pen2 = QPen(QColor(color), max(2, size * 0.07))
    pen2.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen2.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen2)
    p.drawLine(QPointF(w * 0.32, h * 0.52), QPointF(w * 0.45, h * 0.65))
    p.drawLine(QPointF(w * 0.45, h * 0.65), QPointF(w * 0.70, h * 0.35))
    p.end()
    return QIcon(pm)


def icon_events(size=18, color="#e8e8e8"):
    """Lista/documento — pestaña Eventos."""
    pm, p = _canvas(size)
    pen = QPen(QColor(color), max(1.4, size * 0.09))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawRoundedRect(QRectF(size * 0.12, size * 0.08, size * 0.76, size * 0.84), 2, 2)
    for y in (0.30, 0.50, 0.70):
        p.drawLine(QPointF(size * 0.26, size * y), QPointF(size * 0.74, size * y))
    p.end()
    return QIcon(pm)


def icon_alert(size=18, color="#e74c3c"):
    """Triángulo de advertencia — pestaña Alertas."""
    pm, p = _canvas(size)
    p.setPen(QPen(QColor(color), max(1.4, size * 0.09)))
    p.setBrush(Qt.BrushStyle.NoBrush)
    tri = QPolygonF([
        QPointF(size * 0.5, size * 0.06),
        QPointF(size * 0.94, size * 0.90),
        QPointF(size * 0.06, size * 0.90),
    ])
    p.drawPolygon(tri)
    pen2 = QPen(QColor(color), max(1.6, size * 0.12))
    pen2.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen2)
    p.drawLine(QPointF(size * 0.5, size * 0.38), QPointF(size * 0.5, size * 0.62))
    p.drawPoint(QPointF(size * 0.5, size * 0.76))
    p.end()
    return QIcon(pm)


def icon_play(size=16, color="#2ecc71"):
    """Iniciar captura."""
    pm, p = _canvas(size)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    tri = QPolygonF([
        QPointF(size * 0.25, size * 0.15),
        QPointF(size * 0.25, size * 0.85),
        QPointF(size * 0.85, size * 0.5),
    ])
    p.drawPolygon(tri)
    p.end()
    return QIcon(pm)


def icon_stop(size=16, color="#e74c3c"):
    """Detener captura."""
    pm, p = _canvas(size)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    p.drawRoundedRect(QRectF(size * 0.22, size * 0.22, size * 0.56, size * 0.56), 2, 2)
    p.end()
    return QIcon(pm)


def icon_trash(size=16, color="#e8e8e8"):
    """Limpiar."""
    pm, p = _canvas(size)
    pen = QPen(QColor(color), max(1.3, size * 0.09))
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawLine(QPointF(size * 0.20, size * 0.30), QPointF(size * 0.80, size * 0.30))
    p.drawLine(QPointF(size * 0.40, size * 0.30), QPointF(size * 0.40, size * 0.18))
    p.drawLine(QPointF(size * 0.60, size * 0.30), QPointF(size * 0.60, size * 0.18))
    p.drawLine(QPointF(size * 0.40, size * 0.18), QPointF(size * 0.60, size * 0.18))
    path = QPainterPath()
    path.moveTo(size * 0.28, size * 0.32)
    path.lineTo(size * 0.32, size * 0.88)
    path.lineTo(size * 0.68, size * 0.88)
    path.lineTo(size * 0.72, size * 0.32)
    p.drawPath(path)
    p.end()
    return QIcon(pm)