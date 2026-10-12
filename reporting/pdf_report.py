from reporting.html_report import report_body

from PySide6.QtCore import QBuffer, QIODevice
from PySide6.QtGui import QPdfWriter, QTextDocument


def build_pdf_report(manifest):
    """Render the report in RAM; the exporter places it inside the ZIP."""
    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    writer = QPdfWriter(buffer)
    writer.setTitle('TERRA Triage Report')
    writer.setCreator('TERRA')
    document = QTextDocument()
    document.setHtml(report_body(manifest))
    document.print_(writer)
    del writer
    return bytes(buffer.data())
