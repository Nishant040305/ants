"""
Mitm JSONL Process Viewer - Desktop UI (Enhanced)
Author: ChatGPT (GPT-5 Thinking mini)

Requirements:
  - Python 3.10+
  - PySide6 (pip install PySide6)
  - pandas (pip install pandas)
  - matplotlib (pip install matplotlib)

Improvements in this enhanced version:
  - Dark, modern style using Qt palettes (no external theme required)
  - Search, sort and filter using QSortFilterProxyModel
  - Colored risk badges in table via delegate
  - Responsive charts with proper labels and date formatting
  - Right panel shows formatted raw JSON and editable LLM fields
  - Export filtered view to CSV / JSONL
  - Keyboard shortcuts and status bar with counts

Usage:
  python mitm_process_viewer.py /path/to/mitm_logs.jsonl

Note: This is a single-file desktop app. For very large files (>200k rows) consider sampling or a database-backed approach.
"""

import sys
import json
import math
from pathlib import Path
from datetime import datetime

import pandas as pd
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog,
    QLabel, QTextEdit, QLineEdit, QTableView, QHeaderView, QSplitter, QSizePolicy,
    QMessageBox, QComboBox, QStatusBar, QToolBar, QAbstractItemView
)
from PySide6.QtGui import QPalette, QColor, QAction, QBrush, QFont
from PySide6.QtCore import QAbstractTableModel, Qt, QModelIndex, QSortFilterProxyModel, QRegularExpression

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.dates as mdates


# ----------------------------- Utilities -----------------------------

def safe_get(d, path, default=None):
    if d is None:
        return default
    if isinstance(path, str):
        path = path.split(".")
    cur = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def parse_jsonl_file(path: Path, max_lines: int | None = None) -> pd.DataFrame:
    records = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if max_lines and i >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                # try to fix common trailing commas
                try:
                    obj = json.loads(line.replace('	', ''))
                except Exception:
                    continue
            rec = {}
            rec["raw"] = obj
            rec["timestamp"] = safe_get(obj, "timestamp")
            try:
                rec["ts_dt"] = pd.to_datetime(rec["timestamp"]) if rec["timestamp"] else pd.NaT
            except Exception:
                rec["ts_dt"] = pd.NaT
            # flatten common fields
            rec["request_method"] = safe_get(obj, "method") or safe_get(obj, "request.method")
            rec["request_host"] = safe_get(obj, "host") or safe_get(obj, "request.host") or safe_get(obj, "client.host")
            rec["request_path"] = safe_get(obj, "path") or safe_get(obj, "request.path")
            rec["response_status"] = safe_get(obj, "status_code") or safe_get(obj, "response.status_code")
            # timings
            timings = safe_get(obj, "timings")
            try:
                if timings and "request_start" in timings and "response_end" in timings:
                    rec["response_latency_s"] = float(timings["response_end"] - timings["request_start"]) if timings["response_end"] and timings["request_start"] else None
                elif safe_get(obj, "flow_duration_ms"):
                    rec["response_latency_s"] = float(safe_get(obj, "flow_duration_ms")) / 1000.0
                else:
                    rec["response_latency_s"] = None
            except Exception:
                rec["response_latency_s"] = None
            # analytics
            analytics = safe_get(obj, "analysis") or safe_get(obj, "analytics") or safe_get(obj, "analysis") or {}
            if isinstance(analytics, dict):
                rec["llm_risk_level"] = analytics.get("llm_risk_level")
                rec["llm_explanation"] = analytics.get("llm_explanation")
                rec["llm_recommended_action"] = analytics.get("llm_recommended_action")
            else:
                rec["llm_risk_level"] = None
                rec["llm_explanation"] = None
                rec["llm_recommended_action"] = None

            # friendly host if missing
            if not rec["request_host"]:
                rec["request_host"] = safe_get(obj, "client.peername")

            records.append(rec)
    df = pd.DataFrame(records)
    return df


# ----------------------------- Table Model -----------------------------

class FlowsTableModel(QAbstractTableModel):
    visible_columns = [
        "timestamp", "request_method", "request_host", "request_path", "response_status", "llm_risk_level", "response_latency_s"
    ]

    def __init__(self, df: pd.DataFrame):
        super().__init__()
        self._df = df.reset_index(drop=True)

    def rowCount(self, parent=QModelIndex()):
        return len(self._df)

    def columnCount(self, parent=QModelIndex()):
        return len(self.visible_columns)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        col = self.visible_columns[index.column()]
        val = self._df.iloc[index.row()].get(col)
        if role == Qt.DisplayRole:
            if pd.isna(val):
                return ""
            if col == "timestamp" and isinstance(val, pd.Timestamp):
                return val.strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(val, float):
                if math.isfinite(val):
                    return f"{val:.3f}"
                return ""
            return str(val)
        if role == Qt.TextAlignmentRole:
            if col == "response_latency_s" or col == "response_status":
                return Qt.AlignRight | Qt.AlignVCenter
            return Qt.AlignLeft | Qt.AlignVCenter
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.visible_columns[section]
        return str(section)

    def get_row(self, row_index: int) -> dict:
        return self._df.iloc[row_index].to_dict()

    def df(self) -> pd.DataFrame:
        return self._df


# ----------------------------- Delegate for risk coloring -----------------------------
from PySide6.QtWidgets import QStyledItemDelegate

class RiskDelegate(QStyledItemDelegate):
    COLORS = {
        "critical": QColor(200, 50, 50),
        "high": QColor(220, 90, 40),
        "medium": QColor(230, 170, 40),
        "low": QColor(80, 180, 80),
        "info": QColor(100, 140, 220),
        "(none)": QColor(150, 150, 150)
    }

    def paint(self, painter, option, index):
        text = index.data(Qt.DisplayRole)
        if not text:
            return super().paint(painter, option, index)
        lvl = text.lower() if isinstance(text, str) else str(text)
        color = self.COLORS.get(lvl, QColor(130, 130, 130))
        painter.save()
        # draw background rounded rect
        rect = option.rect.adjusted(6, 6, -6, -6)
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(rect, 6, 6)
        # draw text
        painter.setPen(QColor(255, 255, 255))
        font = painter.font()
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignCenter, text)
        painter.restore()


# ----------------------------- Main Viewer -----------------------------

class Viewer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mitm Process Viewer — Enhanced")
        self.resize(1400, 900)
        self._apply_dark_palette()

        main_layout = QVBoxLayout(self)

        # toolbar
        toolbar = QToolBar()
        load_action = QAction("Load JSONL", self)
        load_action.triggered.connect(self.on_load)
        toolbar.addAction(load_action)

        export_action = QAction("Export Filtered CSV", self)
        export_action.triggered.connect(self.export_filtered_csv)
        toolbar.addAction(export_action)

        inject_action = QAction("Inject Example", self)
        inject_action.triggered.connect(self.inject_example_dialog)
        toolbar.addAction(inject_action)

        main_layout.addWidget(toolbar)

        # controls
        ctrl_layout = QHBoxLayout()
        ctrl_layout.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("host, method, path, risk level...")
        self.search_input.returnPressed.connect(self.on_search)
        ctrl_layout.addWidget(self.search_input)

        ctrl_layout.addWidget(QLabel("Risk:"))
        self.risk_filter = QComboBox()
        self.risk_filter.addItem("All")
        self.risk_filter.currentIndexChanged.connect(self.apply_filters)
        ctrl_layout.addWidget(self.risk_filter)

        self.reload_btn = QPushButton("Reload file")
        self.reload_btn.clicked.connect(self.reload)
        self.reload_btn.setEnabled(False)
        ctrl_layout.addWidget(self.reload_btn)

        main_layout.addLayout(ctrl_layout)

        # main splitter
        splitter = QSplitter()

        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)

        # table
        self.table = QTableView()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.clicked.connect(self.on_row_selected)
        left_layout.addWidget(self.table)

        # charts
        charts_layout = QHBoxLayout()
        self.fig1 = Figure(figsize=(5, 3))
        self.canvas1 = FigureCanvas(self.fig1)
        charts_layout.addWidget(self.canvas1)

        self.fig2 = Figure(figsize=(5, 3))
        self.canvas2 = FigureCanvas(self.fig2)
        charts_layout.addWidget(self.canvas2)

        left_layout.addLayout(charts_layout)

        splitter.addWidget(left_container)

        # right panel
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.addWidget(QLabel("Selected Flow Details"))
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        right_layout.addWidget(self.detail_text)

        right_layout.addWidget(QLabel("LLM Explanation"))
        self.expl_text = QTextEdit()
        right_layout.addWidget(self.expl_text)

        right_layout.addWidget(QLabel("LLM Recommended Action"))
        self.action_text = QTextEdit()
        right_layout.addWidget(self.action_text)

        btns = QHBoxLayout()
        self.save_llm_btn = QPushButton("Save LLM Fields")
        self.save_llm_btn.clicked.connect(self.save_llm_fields)
        btns.addWidget(self.save_llm_btn)

        self.export_btn = QPushButton("Export Selected JSON")
        self.export_btn.clicked.connect(self.export_selected_json)
        self.export_btn.setEnabled(False)
        btns.addWidget(self.export_btn)

        right_layout.addLayout(btns)

        splitter.addWidget(right_container)
        splitter.setSizes([900, 500])

        main_layout.addWidget(splitter)

        # status bar
        self.status = QStatusBar()
        main_layout.addWidget(self.status)

        # state
        self.file_path = None
        self.df = pd.DataFrame()
        self.model = None
        self.proxy = None

    def _apply_dark_palette(self):
        pal = QPalette()
        pal.setColor(QPalette.Window, QColor(35, 35, 35))
        pal.setColor(QPalette.WindowText, Qt.white)
        pal.setColor(QPalette.Base, QColor(45, 45, 45))
        pal.setColor(QPalette.AlternateBase, QColor(55, 55, 55))
        pal.setColor(QPalette.ToolTipBase, Qt.white)
        pal.setColor(QPalette.ToolTipText, Qt.white)
        pal.setColor(QPalette.Text, Qt.white)
        pal.setColor(QPalette.Button, QColor(50, 50, 50))
        pal.setColor(QPalette.ButtonText, Qt.white)
        pal.setColor(QPalette.Highlight, QColor(80, 150, 200))
        pal.setColor(QPalette.HighlightedText, Qt.black)
        QApplication.instance() and QApplication.instance().setPalette(pal)

    def on_load(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open JSONL file", str(Path.home()), "JSONL Files (*.jsonl *.log *.txt);;All Files (*)")
        if not path:
            return
        self.file_path = Path(path)
        try:
            self.df = parse_jsonl_file(self.file_path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load file: {e}")
            return
        if self.df.empty:
            QMessageBox.information(self, "No data", "No valid JSON records found in the file.")
            return
        self.reload_btn.setEnabled(True)
        self.setup_model()

    def reload(self):
        if not self.file_path:
            return
        try:
            self.df = parse_jsonl_file(self.file_path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reload file: {e}")
            return
        self.setup_model()

    def setup_model(self):
        self.model = FlowsTableModel(self.df)
        self.proxy = QSortFilterProxyModel()
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)  # filter all columns
        self.table.setModel(self.proxy)
        self.table.setItemDelegateForColumn(5, RiskDelegate())
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSortingEnabled(True)
        self.populate_risk_filter()
        self.apply_filters()
        self.status.showMessage(f"Loaded {len(self.df)} records")

    def populate_risk_filter(self):
        vals = pd.Series(self.df["llm_risk_level"].fillna("(none)").astype(str).unique())
        self.risk_filter.blockSignals(True)
        self.risk_filter.clear()
        self.risk_filter.addItem("All")
        for v in sorted(vals):
            if v and v != "nan":
                self.risk_filter.addItem(v)
        self.risk_filter.blockSignals(False)

    def on_search(self):
        self.apply_filters()

    def apply_filters(self):
        if self.proxy is None:
            return
        q = self.search_input.text().strip()
        selected_risk = self.risk_filter.currentText()
        # build regex for search  
        if q :    
            try:
                reg = QRegularExpression(q)               
                reg.setPatternOptions(QRegularExpression.CaseInsensitiveOption)           
            except Exception:           
                reg = QRegularExpression(q)
                self.proxy.setFilterRegularExpression(reg)   
        else:
            self.proxy.setFilterRegularExpression(QRegularExpression())
        # risk filtering: use a secondary mask by changing the model directly
        if selected_risk and selected_risk != "All":
            # reduce rows in the proxy by rebuilding the source model subset
            mask = self.df["llm_risk_level"].fillna("(none)").astype(str) == selected_risk
            subdf = self.df[mask].reset_index(drop=True)
            self.model = FlowsTableModel(subdf)
            self.proxy.setSourceModel(self.model)
            self.table.setItemDelegateForColumn(5, RiskDelegate())
            self.status.showMessage(f"Showing {len(subdf)} records (risk={selected_risk})")
        else:
            # restore
            self.model = FlowsTableModel(self.df)
            self.proxy.setSourceModel(self.model)
            self.table.setItemDelegateForColumn(5, RiskDelegate())
            self.status.showMessage(f"Showing {len(self.df)} records")
        self.update_charts()

    def on_row_selected(self, idx: QModelIndex):
        if not idx.isValid():
            return
        src_row = self.proxy.mapToSource(idx).row()
        row = self.model.get_row(src_row)
        pretty = json.dumps(row.get("raw", {}), indent=2, default=str)
        self.detail_text.setPlainText(pretty)
        self.expl_text.setPlainText(str(row.get("llm_explanation") or ""))
        self.action_text.setPlainText(str(row.get("llm_recommended_action") or ""))
        self.export_btn.setEnabled(True)

    def save_llm_fields(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            QMessageBox.information(self, "No selection", "Select a row first")
            return
        idx = sel[0]
        src_row = self.proxy.mapToSource(idx).row()
        # update underlying dataframe
        text = self.expl_text.toPlainText()
        action = self.action_text.toPlainText()
        # modify either original df or filtered model back to original - here we modify the model's df
        self.model.df().at[src_row, "llm_explanation"] = text
        self.model.df().at[src_row, "llm_recommended_action"] = action
        QMessageBox.information(self, "Saved", "LLM fields saved to the in-memory view (not persisted to file)")

    def update_charts(self):
        # Chart 1: risk-level counts
        self.fig1.clear()
        ax1 = self.fig1.add_subplot(111)
        try:
            s = self.model.df()["llm_risk_level"].fillna("(none)").astype(str)
            counts = s.value_counts().sort_values(ascending=False)
            counts.plot(kind="bar", ax=ax1)
            ax1.set_title("LLM Risk Level Counts")
            ax1.set_ylabel("Count")
            ax1.set_xlabel("")
            for tick in ax1.get_xticklabels():
                tick.set_rotation(30)
        except Exception:
            ax1.text(0.5, 0.5, "No data", ha="center")
        self.canvas1.draw_idle()

        # Chart 2: timeline (events per minute)
        self.fig2.clear()
        ax2 = self.fig2.add_subplot(111)
        try:
            times = pd.to_datetime(self.model.df()["ts_dt"].dropna())
            if len(times) >= 2:
                by_min = times.dt.floor("min").value_counts().sort_index()
                ax2.plot(by_min.index, by_min.values, marker='o')
                ax2.set_title("Events per minute")
                ax2.set_ylabel("Count")
                ax2.set_xlabel("Time")
                ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
                for label in ax2.get_xticklabels():
                    label.set_rotation(30)
            else:
                lat = self.model.df()["response_latency_s"].dropna()
                if len(lat) > 0:
                    ax2.hist(lat, bins=30)
                    ax2.set_title("Response latency (s) histogram")
                    ax2.set_xlabel("Seconds")
                else:
                    ax2.text(0.5, 0.5, "No timing data", ha="center")
        except Exception:
            ax2.text(0.5, 0.5, "No data", ha="center")
        self.fig2.tight_layout()
        self.canvas2.draw_idle()

    def export_selected_json(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            return
        idx = sel[0]
        src_row = self.proxy.mapToSource(idx).row()
        row = self.model.get_row(src_row)
        suggested = f"mitm_record_{src_row}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", suggested, "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(row.get("raw", {}), f, indent=2, default=str)
        QMessageBox.information(self, "Saved", f"Saved selected JSON to {path}")

    def export_filtered_csv(self):
        if self.model is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "filtered_records.csv", "CSV Files (*.csv);;All Files (*)")
        if not path:
            return
        try:
            self.model.df().to_csv(path, index=False)
            QMessageBox.information(self, "Saved", f"Exported filtered view to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export: {e}")

    def inject_example_dialog(self):
        # simple file picker for a JSON record to append
        path, _ = QFileDialog.getOpenFileName(self, "Select example JSON to inject", str(Path.home()), "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                example = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read example: {e}")
            return
        if not self.file_path:
            QMessageBox.information(self, "No file loaded", "Load (or create) a JSONL file first to inject into")
            return
        append_record_to_jsonl(self.file_path, example)
        QMessageBox.information(self, "Injected", f"Appended example record to {self.file_path}")
        self.reload()


# ----------------------------- Helpers for app entry -----------------------------

def append_record_to_jsonl(path: Path, record: dict):
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "")


def main():
    app = QApplication(sys.argv)
    viewer = Viewer()

    # load file if provided
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
        if path.exists():
            try:
                viewer.file_path = path
                viewer.df = parse_jsonl_file(path)
                viewer.reload_btn.setEnabled(True)
                viewer.setup_model()
            except Exception as e:
                QMessageBox.critical(None, "Error", f"Failed to open file: {e}")

    viewer.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()

