"""
main_window.py
--------------
La ventana principal de la UI.

Se construye por capas:
    5a) Estructura base + panel de control
    5b) (splash.py, archivo aparte)
    5c) Barra de herramientas + tarjetas de estadisticas  <- estamos aqui
    5d) Pestanas Eventos / Alertas con tabla y buscador integrado
    5e) Tema oscuro completo (tablas, pestanas)
    5f) Doble clic en fila -> ventana de detalle

Esta clase NUNCA importa `requests` directamente: todo pasa por
api_client.py, para que si el backend cambia, solo se toque ese archivo.
"""

import requests
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QStatusBar, QFrame, QMessageBox,
)

import api_client
from models import Evento, Estadisticas

# Cada cuanto se refrescan las tarjetas/tablas automaticamente (ms)
INTERVALO_REFRESH_MS = 2500

# Colores de acento (mi propia paleta, no calcada del mockup de Luis)
COLOR_FONDO = "#1c1e26"
COLOR_TARJETA = "#262a35"
COLOR_TEXTO = "#e6e6e6"
COLOR_TEXTO_SECUNDARIO = "#8a94a6"
COLOR_ACENTO = "#3b82f6"        # azul, en vez del verde del mockup
COLOR_ALERTA = "#f59e0b"        # ambar, para "Alertas activas"
COLOR_CRITICO = "#ef4444"       # rojo, para "Severidad >= 4"
COLOR_INFO = "#22c55e"          # verde, para "Tipos detectados"


class TarjetaEstadistica(QFrame):
    """Una tarjeta individual tipo dashboard: un numero grande + una
    etiqueta debajo. Se actualiza llamando a .set_valor(nuevo_numero)."""

    def __init__(self, titulo: str, color: str):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLOR_TARJETA};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)

        self.label_valor = QLabel("0")
        self.label_valor.setStyleSheet(f"color: {color}; font-size: 26px; font-weight: bold;")

        label_titulo = QLabel(titulo)
        label_titulo.setStyleSheet(f"color: {COLOR_TEXTO_SECUNDARIO}; font-size: 11px;")

        layout.addWidget(self.label_valor)
        layout.addWidget(label_titulo)

    def set_valor(self, valor):
        self.label_valor.setText(str(valor))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitor de Amenazas de Red")
        self.resize(1000, 680)
        self.setStyleSheet(f"QMainWindow {{ background-color: {COLOR_FONDO}; }}")

        self.capturando = False

        self._construir_ui()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refrescar)
        self.timer.start(INTERVALO_REFRESH_MS)
        self._refrescar()  # primera carga inmediata

    # ------------------------------------------------------------------
    def _construir_ui(self):
        central = QWidget()
        layout_principal = QVBoxLayout(central)
        layout_principal.setContentsMargins(16, 16, 16, 8)
        layout_principal.setSpacing(12)

        layout_principal.addWidget(self._barra_control())
        layout_principal.addWidget(self._fila_tarjetas())
        layout_principal.addStretch()  # aqui van las pestanas en el paso 5d

        self.setCentralWidget(central)

        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet(f"color: {COLOR_TEXTO_SECUNDARIO};")
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Listo. Backend esperado en http://localhost:8080")

    def _barra_control(self) -> QWidget:
        """Fila superior con los 3 botones + campo de interfaz opcional."""
        contenedor = QWidget()
        layout = QHBoxLayout(contenedor)
        layout.setContentsMargins(0, 0, 0, 0)

        estilo_boton = f"""
            QPushButton {{
                background-color: {COLOR_TARJETA};
                color: {COLOR_TEXTO};
                border: none;
                border-radius: 6px;
                padding: 8px 14px;
            }}
            QPushButton:hover {{ background-color: #2f3440; }}
            QPushButton:disabled {{ color: {COLOR_TEXTO_SECUNDARIO}; }}
        """

        self.btn_iniciar = QPushButton("\u25b6 Iniciar captura")
        self.btn_detener = QPushButton("\u25a0 Detener")
        self.btn_limpiar = QPushButton("\U0001f5d1 Limpiar")
        for b in (self.btn_iniciar, self.btn_detener, self.btn_limpiar):
            b.setStyleSheet(estilo_boton)
        self.btn_detener.setEnabled(False)

        self.btn_iniciar.clicked.connect(self._on_iniciar)
        self.btn_detener.clicked.connect(self._on_detener)
        self.btn_limpiar.clicked.connect(self._on_limpiar)

        self.input_device = QLineEdit()
        self.input_device.setPlaceholderText("interfaz (opcional, ej: eth0)")
        self.input_device.setFixedWidth(180)
        self.input_device.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLOR_TARJETA};
                color: {COLOR_TEXTO};
                border: none;
                border-radius: 6px;
                padding: 6px 10px;
            }}
        """)

        layout.addWidget(self.btn_iniciar)
        layout.addWidget(self.btn_detener)
        layout.addWidget(self.btn_limpiar)
        layout.addStretch()
        layout.addWidget(self.input_device)
        return contenedor

    def _fila_tarjetas(self) -> QWidget:
        """Las 4 tarjetas tipo dashboard, en fila."""
        contenedor = QWidget()
        layout = QHBoxLayout(contenedor)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        self.tarjeta_total = TarjetaEstadistica("Total eventos", COLOR_ACENTO)
        self.tarjeta_alertas = TarjetaEstadistica("Alertas activas", COLOR_ALERTA)
        self.tarjeta_criticos = TarjetaEstadistica("Severidad \u2265 4", COLOR_CRITICO)
        self.tarjeta_tipos = TarjetaEstadistica("Tipos detectados", COLOR_INFO)

        for t in (self.tarjeta_total, self.tarjeta_alertas, self.tarjeta_criticos, self.tarjeta_tipos):
            layout.addWidget(t)
        return contenedor

    # ------------------------------------------------------------------
    # Refresco automatico (timer)
    # ------------------------------------------------------------------
    def _refrescar(self):
        """Trae /events, /alerts y /statistics, y actualiza las tarjetas.
        (Las tablas se conectan en el paso 5d)."""
        try:
            eventos_raw = api_client.obtener_eventos()
            alertas_raw = api_client.obtener_alertas()
            stats_raw = api_client.obtener_estadisticas()
        except requests.exceptions.ConnectionError:
            self.status_bar.showMessage(
                "\u26a0 No se puede conectar al backend. \u00bfEsta corriendo monitor.exe?"
            )
            return
        except requests.exceptions.Timeout:
            self.status_bar.showMessage("\u26a0 El backend tardo demasiado en responder (timeout).")
            return
        except requests.exceptions.RequestException as e:
            self.status_bar.showMessage(f"\u26a0 Error al consultar el backend: {e}")
            return

        eventos = [Evento.desde_dict(e) for e in eventos_raw]
        alertas = [Evento.desde_dict(e) for e in alertas_raw]
        stats = Estadisticas.desde_dict(stats_raw)

        self._actualizar_tarjetas(stats, alertas)
        self.status_bar.showMessage(f"Conectado \u2014 {len(eventos)} eventos totales")

    def _actualizar_tarjetas(self, stats: Estadisticas, alertas: list[Evento]):
        self.tarjeta_total.set_valor(stats.total_paquetes)
        self.tarjeta_alertas.set_valor(len(alertas))

        # Severidad >= 4: sumar las cantidades de las claves "4" y "5"
        # del dict amenazas_por_severidad (las claves llegan como texto)
        criticos = sum(
            cant for sev, cant in stats.amenazas_por_severidad.items()
            if int(sev) >= 4
        )
        self.tarjeta_criticos.set_valor(criticos)

        self.tarjeta_tipos.set_valor(len(stats.amenazas_por_tipo))

    # ------------------------------------------------------------------
    # Botones del panel de control
    # ------------------------------------------------------------------
    def _on_iniciar(self):
        device = self.input_device.text().strip() or None
        try:
            resp = api_client.iniciar_captura(device)
        except requests.exceptions.ConnectionError:
            QMessageBox.warning(
                self, "Sin conexion",
                "No se pudo conectar al backend.\nCorre monitor.exe primero."
            )
            return
        except requests.exceptions.Timeout:
            QMessageBox.warning(
                self, "Sin respuesta",
                "El backend no respondio a tiempo (timeout).\n"
                "Puede que /start este colgado del lado del backend."
            )
            return
        except requests.exceptions.RequestException as e:
            QMessageBox.warning(self, "Error", str(e))
            return

        self.capturando = True
        self.btn_iniciar.setEnabled(False)
        self.btn_detener.setEnabled(True)
        self.status_bar.showMessage(f"Captura iniciada: {resp.get('status')}")

    def _on_detener(self):
        try:
            resp = api_client.detener_captura()
        except requests.exceptions.RequestException as e:
            QMessageBox.warning(self, "Error", str(e))
            return

        self.capturando = False
        self.btn_iniciar.setEnabled(True)
        self.btn_detener.setEnabled(False)
        self.status_bar.showMessage(f"Captura detenida: {resp.get('status')}")

    def _on_limpiar(self):
        try:
            api_client.limpiar_eventos()
        except requests.exceptions.RequestException as e:
            QMessageBox.warning(self, "Error", str(e))
            return
        self.status_bar.showMessage("Eventos limpiados en el backend")

    # ------------------------------------------------------------------
    def closeEvent(self, event):
        self.timer.stop()
        super().closeEvent(event)