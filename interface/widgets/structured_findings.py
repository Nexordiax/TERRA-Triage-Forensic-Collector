"""Lazy table model keeps large parsed result sets out of widget item trees."""
import json
from PySide6.QtCore import Qt, QAbstractTableModel, Signal
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTableView, QPlainTextEdit, QSplitter


class FindingModel(QAbstractTableModel):
    def __init__(self, entries, parent=None):
        super().__init__(parent)
        self.entries = entries
        self.columns = list(dict.fromkeys(['type','locator'] + [key for row in entries for key in row]))

    def rowCount(self,parent=None):
        return 0 if parent and parent.isValid() else len(self.entries)

    def columnCount(self,parent=None):
        return 0 if parent and parent.isValid() else len(self.columns)

    def data(self,index,role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role not in (Qt.ItemDataRole.DisplayRole,Qt.ItemDataRole.ToolTipRole):
            return None
        value = self.entries[index.row()].get(self.columns[index.column()])
        if value is None:
            return ''
        text = json.dumps(value,ensure_ascii=True) if isinstance(value,(dict,list)) else str(value)
        return text if role == Qt.ItemDataRole.ToolTipRole else text[:500]

    def headerData(self,section,orientation,role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        return self.columns[section] if orientation == Qt.Orientation.Horizontal else str(section+1)


class StructuredFindings(QWidget):
    preview_requested = Signal(dict)
    def __init__(self, parsed, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        status = QLabel(f"{parsed['artifact_id']} · {parsed['status']} · {parsed['record_count']} parsed records")
        status.setTextFormat(Qt.TextFormat.PlainText)
        status.setWordWrap(True)
        layout.addWidget(status)
        notes = '\n'.join([parsed.get('error',''), *parsed.get('limitations',[])])
        if notes.strip():
            note = QLabel(notes)
            note.setTextFormat(Qt.TextFormat.PlainText)
            note.setWordWrap(True)
            layout.addWidget(note)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = QTableView()
        self.model = FindingModel(parsed.get('entries',[]),self)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setWordWrap(False)
        self.table.horizontalHeader().setDefaultSectionSize(180)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        layout.addWidget(splitter,1)
        self.table.doubleClicked.connect(self.preview_row)
        self.table.selectionModel().currentRowChanged.connect(self.select_row)
        self.details.setPlainText(json.dumps({key:value for key,value in parsed.items() if key != 'entries'},indent=2,ensure_ascii=True))

    def select_row(self,current,previous):
        if current.isValid():
            self.details.setPlainText(json.dumps(self.model.entries[current.row()],indent=2,ensure_ascii=True))

    def preview_row(self, index):
        if index.isValid():
            spec = self.model.entries[index.row()].get('preview')
            if spec:
                self.preview_requested.emit(spec)
