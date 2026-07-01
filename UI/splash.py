"""
splash.py
---------
Pantalla de carga que se muestra unos segundos al abrir la app,
antes de la ventana principal. Es puramente cosmetico: no habla
con el backend ni depende de main_window.py.
"""

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QProgressBar
from PySide6.QtGui import QFont

# Tiempo total que se muestra el splash, en milisegundos
DURACION_MS = 1800
# Cada cuanto avanza la barra de progreso (mas chico = mas fluido)
INTERVALO_MS = 40


class SplashScreen(QWidget):
    def __init__(self, on_finish):
        """
        on_finish: funcion que se llama automaticamente cuando el
        splash termina (normalmente: abrir la ventana principal).
        """
        super().__init__()
        self._on_finish = on_finish
        self._progreso = 0

        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        self.setFixedSize(420, 260)
        self.setStyleSheet("""
            QWidget {
                background-color: #14161c;
                border-radius: 12px;
            }
            QLabel#titulo {
                color: #e8e8e8;
                font-size: 20px;
                font-weight: bold;
            }
            QLabel#subtitulo {
                color: #7a8699;
                font-size: 11px;
                letter-spacing: 1px;
            }
            QLabel#estado {
                color: #8a94a6;
                font-size: 11px;
            }
            QProgressBar {
                background-color: #23262f;
                border: none;
                border-radius: 4px;
                height: 6px;
            }
            QProgressBar::chunk {
                background-color: #3b82f6;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 30)
        layout.setSpacing(6)
        layout.addStretch()

        titulo = QLabel("Monitor de Amenazas")
        titulo.setObjectName("titulo")
        titulo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitulo = QLabel("SISTEMA DE MONITOREO EN RED")
        subtitulo.setObjectName("subtitulo")
        subtitulo.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(titulo)
        layout.addWidget(subtitulo)
        layout.addSpacing(20)

        self.barra = QProgressBar()
        self.barra.setRange(0, 100)
        self.barra.setTextVisible(False)
        layout.addWidget(self.barra)

        self.label_estado = QLabel("Iniciando sistema...")
        self.label_estado.setObjectName("estado")
        layout.addWidget(self.label_estado)

        layout.addStretch()

        # Timer que va avanzando la barra hasta llegar a 100%
        self._pasos_totales = DURACION_MS // INTERVALO_MS
        self._paso_actual = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._avanzar)
        self.timer.start(INTERVALO_MS)

    def _avanzar(self):
        self._paso_actual += 1
        porcentaje = int((self._paso_actual / self._pasos_totales) * 100)
        self.barra.setValue(min(porcentaje, 100))

        if self._paso_actual >= self._pasos_totales:
            self.timer.stop()
            self.close()
            self._on_finish()