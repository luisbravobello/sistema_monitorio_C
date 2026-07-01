from PySide6.QtCore import Qt, QTimer, QPointF
from PySide6.QtGui import (QFont, QColor, QPainter, QLinearGradient,
                            QPen, QPixmap, QPainterPath, QBrush, QConicalGradient)
from PySide6.QtWidgets import QSplashScreen


class SplashScreen(QSplashScreen):
    def __init__(self):
        px = QPixmap(560, 340)
        px.fill(QColor("#0a0a0f"))
        super().__init__(px, Qt.WindowType.WindowStaysOnTopHint)
        self._progress = 0
        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(50)

    def _tick(self):
        self._progress += 1
        self.repaint()
        if self._progress >= 100:
            self._timer.stop()

    def is_done(self):
        return self._progress >= 100

    def drawContents(self, painter: QPainter):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        # Fondo con gradiente sutil
        bg = QLinearGradient(0, 0, 0, h)
        bg.setColorAt(0.0, QColor("#0f0f1a"))
        bg.setColorAt(1.0, QColor("#080810"))
        painter.fillRect(0, 0, w, h, bg)

        # Línea decorativa superior verde
        pen = QPen(QColor("#00c853"), 2)
        painter.setPen(pen)
        painter.drawLine(0, 0, int(w * self._progress / 100), 0)

        # ── Círculo exterior ──
        cx, cy = w // 2, 105
        painter.setPen(QPen(QColor("#1a2a1a"), 1))
        painter.setBrush(QColor("#0d1f0d"))
        painter.drawEllipse(cx - 45, cy - 45, 90, 90)

        # Arco de progreso circular alrededor del ícono
        arc_pen = QPen(QColor("#00c853"), 3)
        arc_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(arc_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        span = int(360 * 16 * self._progress / 100)
        painter.drawArc(cx - 45, cy - 45, 90, 90, 90 * 16, -span)

        # ── Ícono: escudo vectorial ──
        shield = QPainterPath()
        sx, sy, sw, sh = cx - 18, cy - 22, 36, 44
        shield.moveTo(sx + sw / 2, sy)
        shield.lineTo(sx + sw, sy + sh * 0.28)
        shield.lineTo(sx + sw, sy + sh * 0.52)
        shield.quadTo(sx + sw, sy + sh * 0.85, sx + sw / 2, sy + sh)
        shield.quadTo(sx, sy + sh * 0.85, sx, sy + sh * 0.52)
        shield.lineTo(sx, sy + sh * 0.28)
        shield.closeSubpath()

        shield_grad = QLinearGradient(sx, sy, sx, sy + sh)
        shield_grad.setColorAt(0.0, QColor("#00c853"))
        shield_grad.setColorAt(1.0, QColor("#007a33"))
        painter.setBrush(QBrush(shield_grad))
        painter.setPen(QPen(QColor("#00ff6a"), 1))
        painter.drawPath(shield)

        # Check dentro del escudo
        ck = QPen(QColor("#ffffff"), 2.2)
        ck.setCapStyle(Qt.PenCapStyle.RoundCap)
        ck.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        painter.setPen(ck)
        painter.drawLine(cx - 8, cy + 3, cx - 2, cy + 9)
        painter.drawLine(cx - 2, cy + 9, cx + 10, cy - 5)

        # ── Título ──
        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("Segoe UI", 19, QFont.Weight.Bold))
        painter.drawText(0, 170, w, 32, Qt.AlignmentFlag.AlignCenter, "Monitor de Amenazas")

        # ── Subtítulo ──
        painter.setPen(QColor("#00c853"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Normal))
        painter.drawText(0, 202, w, 20, Qt.AlignmentFlag.AlignCenter,
                         "SISTEMA DE MONITOREO EN RED")

        # Separador
        painter.setPen(QPen(QColor("#1a2a1a"), 1))
        painter.drawLine(80, 228, w - 80, 228)

        # ── Barra de progreso ──
        bx, by, bw, bh = 70, 248, w - 140, 6
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#111111"))
        painter.drawRoundedRect(bx, by, bw, bh, 3, 3)

        fw = int(bw * self._progress / 100)
        if fw > 0:
            bar_grad = QLinearGradient(bx, 0, bx + bw, 0)
            bar_grad.setColorAt(0.0, QColor("#007a33"))
            bar_grad.setColorAt(1.0, QColor("#00c853"))
            painter.setBrush(QBrush(bar_grad))
            painter.drawRoundedRect(bx, by, fw, bh, 3, 3)

        # ── Texto ──
        painter.setPen(QColor("#4a4a4a"))
        painter.setFont(QFont("Segoe UI", 8))
        painter.drawText(bx, 265, 120, 16, Qt.AlignmentFlag.AlignLeft, "Iniciando sistema...")
        painter.drawText(0, 265, w - bx, 16, Qt.AlignmentFlag.AlignRight,
                         f"{self._progress}%")

        # ── Puntos decorativos ──
        for i, color in enumerate(["#00c853", "#007a33", "#004d1f"]):
            painter.setBrush(QColor(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(w // 2 - 16 + i * 16, 305, 5, 5)

        # Versión
        painter.setPen(QColor("#222222"))
        painter.setFont(QFont("Segoe UI", 8))
        painter.drawText(0, 320, w - 10, 16, Qt.AlignmentFlag.AlignRight, "v1.0.0")


