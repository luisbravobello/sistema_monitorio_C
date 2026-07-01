"""
main.py
-------
Punto de entrada de la aplicacion. Este es el unico archivo que se
ejecuta directamente (python main.py); todos los demas (api_client,
models, main_window) son modulos que este archivo importa y usa.

Requisitos para correrlo:
    1. Tener el entorno virtual activado:  venv\\Scripts\\activate
    2. Tener el backend corriendo en http://localhost:8080
       (aunque si el backend no responde, la UI igual abre —
       simplemente vas a ver mensajes de error en la barra de estado
       cuando intente conectarse, en vez de que la app truene).
"""

import sys
from PySide6.QtWidgets import QApplication
from main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    ventana = MainWindow()
    ventana.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()