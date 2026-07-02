from datetime import datetime
from PySide6.QtCore import QTimer, QThread, Signal, Qt, QAbstractTableModel, QModelIndex
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableView, QHeaderView,
    QLabel, QStatusBar, QTabWidget, QLineEdit, QDialog,
    QDialogButtonBox, QFormLayout, QFrame,
)
from api_client import ApiClient

SEV_COLORS = {1:"#4a90d9", 2:"#27ae60", 3:"#f39c12", 4:"#e67e22", 5:"#e74c3c"}
SEV_LABELS = {1:"Baja",    2:"Media",   3:"Alta",    4:"Crítica", 5:"Máxima"}
EV_COLS  = ["#", "IP Origen", "Puerto", "Tipo", "Severidad", "Fecha / Hora"]
ALT_COLS = ["#", "IP Origen", "Puerto", "Tipo", "Severidad", "Confirmada", "Fecha / Hora"]


def _fmt_ts(ts):
    try:    return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except: return str(ts)


# ── Modelo de tabla virtual (solo renderiza filas visibles) ──────────────────
class EventModel(QAbstractTableModel):
    def __init__(self, cols, is_alert=False):
        super().__init__()
        self._cols     = cols
        self._is_alert = is_alert
        self._rows     = []   # lista de dicts

    def replace(self, rows):
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def row_at(self, row: int):
        """Devuelve el dict de la fila tal como se ve ACTUALMENTE en la
        tabla (ya filtrada/buscada), no de la lista completa sin filtrar."""
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def rowCount(self, parent=QModelIndex()):    return len(self._rows)
    def columnCount(self, parent=QModelIndex()): return len(self._cols)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self._cols[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        e   = self._rows[index.row()]
        col = index.column()
        sev = e['severidad']

        if role == Qt.ItemDataRole.DisplayRole:
            if self._is_alert:
                vals = [
                    e['id'],
                    e['ip'],
                    e['puerto'],
                    e['tipo'],
                    SEV_LABELS.get(sev, '?'),
                    "✔ Sí" if e.get('confirmed') else "✖ No",
                    _fmt_ts(e['timestamp']),
                ]
            else:
                vals = [
                    e['id'],
                    e['ip'],
                    e['puerto'],
                    e['tipo'],
                    SEV_LABELS.get(sev, '?'),
                    _fmt_ts(e['timestamp']),
                ]
            return str(vals[col])

        if role == Qt.ItemDataRole.ForegroundRole:
            # Columna Severidad esta en el indice 4 en AMBAS tablas
            # (Eventos y Alertas), ya que "Confirmada" se agrego DESPUES
            # de Severidad en ALT_COLS, no antes.
            if col == 4:
                return QBrush(QColor(SEV_COLORS.get(sev, "#888")))
            if self._is_alert and col == 5:  # columna Confirmada
                return QBrush(QColor("#27ae60" if e.get('confirmed') else "#888"))

        if role == Qt.ItemDataRole.TextAlignmentRole:
            center_cols = {0, 2, 4, 5, 6} if self._is_alert else {0, 2, 4, 5}
            if col in center_cols:
                return Qt.AlignmentFlag.AlignCenter

        return None


def _make_view(model):
    v = QTableView()
    v.setModel(model)
    v.horizontalHeader().setStretchLastSection(True)
    v.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    v.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
    v.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
    v.setAlternatingRowColors(True)
    v.verticalHeader().setVisible(False)
    return v


# ── Diálogo de detalle ───────────────────────────────────────────────────────
class DetailDialog(QDialog):
    def __init__(self, event, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Detalle — Evento #{event['id']}")
        self.setMinimumWidth(400)
        lay = QFormLayout(self)
        lay.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        sev = event['severidad']
        for label, val, color in [
            ("ID",         event['id'],      None),
            ("IP Origen",  event['ip'],      None),
            ("Puerto",     event['puerto'],  None),
            ("Tipo",       event['tipo'],    None),
            ("Severidad",  SEV_LABELS.get(sev, '?'), SEV_COLORS.get(sev)),
            ("Confirmada", "Sí" if event.get('confirmed') else "No", None),
            ("Timestamp",  _fmt_ts(event['timestamp']), None),
        ]:
            lbl = QLabel(str(val))
            if color: lbl.setStyleSheet(f"color:{color};font-weight:bold;")
            lay.addRow(f"<b>{label}</b>", lbl)
        sep = QFrame(); sep.setFrameShape(QFrame.Shape.HLine)
        lay.addRow(sep)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        lay.addRow(btns)


# ── Worker de red (hilo secundario) ─────────────────────────────────────────
class ApiWorker(QThread):
    done = Signal(object, str)

    def __init__(self, fn, action):
        super().__init__()
        self.fn     = fn
        self.action = action
        self.setTerminationEnabled(False)

    def run(self):
        try:    self.done.emit(self.fn(), self.action)
        except Exception as e: self.done.emit({"error": str(e)}, self.action)

    def cleanup(self):
        self.wait(2000)
        if not self.isFinished():
            self.quit()


# ── Ventana principal ────────────────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitor de Amenazas en Red")
        self.resize(1100, 680)
        self.api          = ApiClient()
        self._worker      = None
        self._aux_workers = []
        self._events      = []
        self._alerts      = []
        self._last_hash   = (-1, -1)

        central = QWidget()
        root    = QVBoxLayout(central)
        root.setSpacing(6)
        root.setContentsMargins(8, 8, 8, 4)

        # ── Botones ──────────────────────────────────────────────────
        top = QHBoxLayout()
        self.start_btn = QPushButton("▶  Iniciar captura")
        self.stop_btn  = QPushButton("■  Detener")
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("🗑  Limpiar")
        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn.clicked.connect(self._on_stop)
        self.clear_btn.clicked.connect(self._on_clear)
        top.addWidget(self.start_btn)
        top.addWidget(self.stop_btn)
        top.addWidget(self.clear_btn)
        top.addStretch()
        root.addLayout(top)

        # ── Tarjetas ─────────────────────────────────────────────────
        sr = QHBoxLayout(); sr.setSpacing(8)
        self._c_total  = self._card("Total eventos",    "—", "#4a90d9")
        self._c_alerts = self._card("Alertas activas",  "—", "#e74c3c")
        self._c_high   = self._card("Severidad",    "—", "#e67e22")
        self._c_types  = self._card("Tipos detectados", "—", "#27ae60")
        for c in [self._c_total, self._c_alerts, self._c_high, self._c_types]:
            sr.addWidget(c)
        root.addLayout(sr)

        # ── Tabs ─────────────────────────────────────────────────────
        tabs = QTabWidget()

        # Tab eventos
        te = QWidget(); le = QVBoxLayout(te); le.setSpacing(4)
        fr = QHBoxLayout()
        fr.addWidget(QLabel("IP:"))
        self.f_ip   = QLineEdit(); self.f_ip.setPlaceholderText("10.0.0.1")
        fr.addWidget(self.f_ip)
        fr.addWidget(QLabel("Puerto:"))
        self.f_port = QLineEdit(); self.f_port.setPlaceholderText("22"); self.f_port.setFixedWidth(70)
        fr.addWidget(self.f_port)
        b_search = QPushButton("Buscar");  b_search.clicked.connect(self._on_search)
        b_clear  = QPushButton("Limpiar"); b_clear.clicked.connect(self._clear_filter)
        fr.addWidget(b_search); fr.addWidget(b_clear); fr.addStretch()
        le.addLayout(fr)
        le.addWidget(QLabel("Doble clic → ver detalle", alignment=Qt.AlignmentFlag.AlignRight))
        self._ev_model = EventModel(EV_COLS, is_alert=False)
        self.ev_view   = _make_view(self._ev_model)
        self.ev_view.doubleClicked.connect(self._detail_event)
        le.addWidget(self.ev_view)
        tabs.addTab(te, "📋  Eventos")

        # Tab alertas
        ta = QWidget(); la = QVBoxLayout(ta); la.setSpacing(4)
        sr2 = QHBoxLayout(); sr2.addWidget(QLabel("Severidad mínima:"))
        self.sev_btns = {}
        for s in range(1, 6):
            b = QPushButton(SEV_LABELS[s])
            b.setCheckable(True)
            b.setStyleSheet(f"QPushButton:checked{{background:{SEV_COLORS[s]};color:white;}}")
            b.clicked.connect(lambda _, sv=s: self._filter_alerts(sv))
            sr2.addWidget(b); self.sev_btns[s] = b
        sr2.addStretch(); la.addLayout(sr2)
        la.addWidget(QLabel("Doble clic → ver detalle", alignment=Qt.AlignmentFlag.AlignRight))
        self._alt_model = EventModel(ALT_COLS, is_alert=True)
        self.alt_view   = _make_view(self._alt_model)
        self.alt_view.doubleClicked.connect(self._detail_alert)
        la.addWidget(self.alt_view)
        tabs.addTab(ta, "🚨  Alertas")

        root.addWidget(tabs)
        self.setCentralWidget(central)

        self.sb = QStatusBar(); self.setStatusBar(self.sb)
        self.sb.showMessage("Desconectado — inicia el servidor C primero")

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(4000)

    # ── Helpers ──────────────────────────────────────────────────────
    def _card(self, title, val, color):
        f = QFrame(); f.setFrameShape(QFrame.Shape.StyledPanel)
        f.setStyleSheet(f"QFrame{{border-left:4px solid {color};padding:4px 8px;}}")
        l = QVBoxLayout(f); l.setSpacing(1)
        v = QLabel(val); v.setStyleSheet(f"font-size:22px;font-weight:bold;color:{color};")
        t = QLabel(title); t.setStyleSheet("font-size:11px;color:gray;")
        l.addWidget(v); l.addWidget(t); f._v = v
        return f

    def _to_dict(self, i, e):
        return {"id": i+1, "ip": e.ip, "puerto": e.puerto, "tipo": e.tipo,
                "severidad": e.severidad, "timestamp": e.timestamp,
                "confirmed": getattr(e, 'confirmed', 0)}

    def _run_aux(self, fn, action):
        w = ApiWorker(fn, action)
        w.done.connect(self._on_done)
        w.finished.connect(lambda: self._aux_workers.remove(w) if w in self._aux_workers else None)
        self._aux_workers.append(w)
        w.start()

    # ── Refresh principal ─────────────────────────────────────────────
    def _refresh(self):
        if self._worker and self._worker.isRunning():
            return
        self._worker = ApiWorker(
            lambda: (self.api.get_events(), self.api.get_alerts(), self.api.get_statistics()),
            "refresh"
        )
        self._worker.done.connect(self._on_done)
        self._worker.start()

    # ── Handler central ───────────────────────────────────────────────
    def _on_done(self, result, action):
        if isinstance(result, dict) and "error" in result:
            if action in ("start", "stop"):
                self.sb.showMessage(f"Error: {result['error']}")
                self.start_btn.setEnabled(True)
            return

        if action == "refresh":
            events, alerts, stats = result

            # Fix #2: si el backend no respondio, get_events()/get_alerts()
            # devuelven None (no []) para distinguir "0 eventos reales"
            # de "no hay conexion". Cortamos aqui y avisamos.
            if events is None or alerts is None:
                self.sb.showMessage("Sin conexión con el servidor C")
                return

            self._events = [self._to_dict(i, e) for i, e in enumerate(events)]
            self._alerts = [self._to_dict(i, e) for i, e in enumerate(alerts)]

            # Fix #4: /alerts del backend YA filtra solo eventos
            # confirmados (SSH_BRUTE siempre es confirmed=1 del lado
            # de C), asi que marcarlo aqui no es inventar el dato,
            # es reflejar una garantia real de ese endpoint.
            for a in self._alerts:
                a['confirmed'] = 1

            h = (len(self._events), len(self._alerts))
            if h != self._last_hash:
                self._last_hash = h
                self._ev_model.replace(self._events)
                self._alt_model.replace(self._alerts)
                high  = sum(1 for e in self._events if e['severidad'] >= 4)
                tipos = len(set(e['tipo'] for e in self._events))
                self._c_total._v.setText(str(len(self._events)))
                self._c_alerts._v.setText(str(len(self._alerts)))
                self._c_high._v.setText(str(high))
                self._c_types._v.setText(str(tipos))

            if stats:
                self.sb.showMessage(
                    f"Total: {stats.total_paquetes} paquetes  |  {datetime.now().strftime('%H:%M:%S')}")
            else:
                self.sb.showMessage(f"Conectado — {datetime.now().strftime('%H:%M:%S')}")

        elif action == "start":
            self.stop_btn.setEnabled(True)
            self.sb.showMessage("Capturando…")
            self._last_hash = (-1, -1)
            self._refresh()

        elif action == "stop":
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self._clear_ui()
            self.sb.showMessage("Detenido — registros limpiados")

        elif action == "search":
            self._ev_model.replace(result)

        elif action == "clear_done":
            self._clear_ui()
            self.sb.showMessage("Registros limpiados")

        elif action == "filter_alerts":
            self._alt_model.replace(result)

    # ── Detalles ─────────────────────────────────────────────────────
    def _detail_event(self, index):
        e = self._ev_model.row_at(index.row())
        if e: DetailDialog(e, self).exec()

    def _detail_alert(self, index):
        e = self._alt_model.row_at(index.row())
        if e: DetailDialog(e, self).exec()

    # ── Filtros ──────────────────────────────────────────────────────
    def _on_search(self):
        ip   = self.f_ip.text().strip() or None
        port = int(self.f_port.text()) if self.f_port.text().strip().isdigit() else None
        snap = self._events[:]
        self._run_aux(
            lambda: [e for e in snap if (not ip or e['ip']==ip) and (not port or e['puerto']==port)],
            "search"
        )

    def _clear_filter(self):
        self.f_ip.clear(); self.f_port.clear()
        self._ev_model.replace(self._events)

    def _filter_alerts(self, min_sev):
        for s, b in self.sev_btns.items(): b.setChecked(s == min_sev)
        snap = self._alerts[:]
        self._run_aux(lambda: [e for e in snap if e['severidad'] >= min_sev], "filter_alerts")

    # ── Control ──────────────────────────────────────────────────────
    def _clear_ui(self):
        self._events = []; self._alerts = []
        self._last_hash = (-1, -1)
        self._ev_model.replace([])
        self._alt_model.replace([])
        for card in [self._c_total, self._c_alerts, self._c_high, self._c_types]:
            card._v.setText("—")

    def _on_clear(self):
        self._run_aux(self.api.clear, "clear_done")

    def _on_start(self):
        self.start_btn.setEnabled(False)
        self._run_aux(self.api.start, "start")

    def _on_stop(self):
        self.stop_btn.setEnabled(False)
        self._run_aux(self.api.stop, "stop")

    # ── Cleanup ──────────────────────────────────────────────────────
    def closeEvent(self, event):
        self._timer.stop()
        if self._worker:
            self._worker.cleanup()
        for w in list(self._aux_workers):
            w.cleanup()
        super().closeEvent(event)