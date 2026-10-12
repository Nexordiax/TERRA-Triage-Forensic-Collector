from PySide6.QtCore import QObject


class NavigationController(QObject):
    """Keep page history for both case and quick-triage workflows."""

    def __init__(self, stack):
        super().__init__(stack)
        self.stack = stack
        self.history = []

    def open(self, page):
        current = self.stack.currentWidget()
        if current is not page:
            self.history.append(current)
            self.stack.setCurrentWidget(page)

    def back(self):
        if self.history:
            self.stack.setCurrentWidget(self.history.pop())
