import sys
from PySide6.QtWidgets import QApplication
from splash import SplashScreen
from main_window import MainWindow

def main():
    app = QApplication(sys.argv)

    # Ventana en una lista para evitar que el Garbage Collector la borre
    ventana_principal = []

    # 1. Instanciar el splash animado
    splash = SplashScreen()
    splash.show()

    def verificar_progreso():
        """ Revisa periódicamente si el splash llegó al 100% """
        if splash.is_done():
            timer_espera.stop()
            
            # Instancia y muestra el panel principal
            ventana = MainWindow()
            ventana.show()
            ventana_principal.append(ventana)
            
            # Cierra el splash de forma limpia
            splash.finish(ventana)
            
    # Creamos un timer en main para monitorear el fin del splash de forma asíncrona
    from PySide6.QtCore import QTimer
    timer_espera = QTimer()
    timer_espera.timeout.connect(verificar_progreso)
    timer_espera.start(50) # Revisa cada 50ms a la par de la animación

    sys.exit(app.exec())

if __name__ == "__main__":
    main()