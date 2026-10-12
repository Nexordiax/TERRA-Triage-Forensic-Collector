import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ['QT_QPA_PLATFORMTHEME'] = 'generic'

from PySide6.QtCore import QBuffer, QEventLoop, QIODevice, QTimer
from PySide6.QtGui import QImage
from PySide6.QtWidgets import QApplication
from artifacts.file_collector import FileCollector, CollectionCancelled
from artifacts.registry import category_for
from controllers.scan_controller import ScanEngine, ScanController
from interface.main_window import MainWindow
from interface.widgets.media_preview import MediaPreview
from storage.memory_store import MemoryStore


def configuration(mode='all_supported', hashes=None, keywords=None, **options):
    return {'collection_mode': mode, 'hashes': hashes or [], 'keywords': keywords or [],
            'hash_files': [], 'keyword_files': [],
            'options': dict(folder_names=False, file_names=False, file_contents=False,
                            hash_matches=False, **{}) | options}


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def file(self, name, data=b'evidence'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def run_engine(self, config=None, targets=None, store=None, **kwargs):
        store = store if store is not None else MemoryStore()
        engine = ScanEngine(targets or {'paths': [str(self.root)]}, config or configuration(), store, **kwargs)
        return engine.run(), store

    def test_collect_categories_bytes_and_integrity(self):
        sources = {
            'photo.jpg': 'Pictures', 'video.mp4': 'Videos', 'sound.wav': 'Audio',
            'report.pdf': 'Documents', '.mozilla/firefox/profile/places.sqlite': 'Browsers',
            'mail.eml': 'Email', '.config/Signal/sql/db.sqlite': 'Communication',
            'etc/os-release': 'Device Information', 'var/log/auth.log': 'OS Activity',
            'unclassified.bin': 'Other Files',
        }
        for name in sources:
            self.file(name)
        before = {str(path): path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        summary, store = self.run_engine()
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(summary['collected'], len(sources))
        self.assertEqual({record['category'] for record in store.records}, set(sources.values()))
        for record in store.records:
            self.assertEqual(record['data'], b'evidence')
            self.assertEqual(record['sha256'], hashlib.sha256(b'evidence').hexdigest())
        after = {str(path): path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(before, after)

    def test_matches_only_all_hash_algorithms_and_keywords(self):
        data = b'prefix Secret phrase suffix'
        source = self.file('secret-file.bin', data)
        self.file('unmatched.jpg')
        folder = self.root / 'secret-folder'
        folder.mkdir()
        hashes = [hashlib.new(name, data, usedforsecurity=False).hexdigest()
                  for name in ('md5', 'sha1', 'sha256', 'sha512')]
        config = configuration('matches_only', hashes, ['SECRET'], folder_names=True,
                               file_names=True, file_contents=True, hash_matches=True)
        summary, store = self.run_engine(config)
        self.assertEqual(summary['collected'], 2)
        record = next(record for record in store.records if record['path'] == str(source))
        self.assertEqual(set(record['matches']['hashes']), {'md5', 'sha1', 'sha256', 'sha512'})
        self.assertEqual(record['matches']['file_names'], ['SECRET'])
        self.assertEqual(record['matches']['file_contents'], ['SECRET'])
        directory = next(record for record in store.records if record['kind'] == 'directory')
        self.assertEqual(directory['data'], b'')
        self.assertEqual(directory['collection'], 'directory metadata')

    def test_content_multibyte_and_name_only_does_not_read_unmatched(self):
        self.file('unknown.bin', 'Grüße'.encode())
        summary, _ = self.run_engine(configuration('matches_only', keywords=['GRÜSSE'], file_contents=True))
        self.assertEqual(summary['collected'], 1)
        collector = FileCollector()
        with patch.object(collector, 'collect', side_effect=AssertionError('Unmatched file was read')):
            summary, _ = self.run_engine(configuration('matches_only', keywords=['absent'], file_names=True), collector=collector)
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(summary['collected'], 0)

    def test_overlap_symlinks_and_special_files(self):
        path = self.file('nested/source.txt')
        (self.root / 'link.txt').symlink_to(path)
        (self.root / 'loop').symlink_to(self.root, target_is_directory=True)
        os.mkfifo(self.root / 'pipe.txt')
        summary, store = self.run_engine(targets={'paths': [str(self.root), str(path.parent)]})
        self.assertEqual(summary['collected'], 1)
        self.assertEqual(store.records[0]['path'], str(path))
        with self.assertRaises(OSError):
            FileCollector().collect(str(self.root / 'link.txt'), lambda: False)

    def test_errors_are_not_collected(self):
        path = self.file('denied.txt')
        collector = FileCollector()
        with patch.object(collector, 'collect', side_effect=PermissionError('access denied')):
            summary, store = self.run_engine(collector=collector)
        self.assertEqual(summary['status'], 'completed_with_errors')
        self.assertEqual(summary['collected'], 0)
        self.assertEqual(store.diagnostics[0]['path'], str(path))
        self.assertIn('access denied', store.diagnostics[0]['message'])

    def test_size_limits_and_total_memory_limit(self):
        self.file('oversize.txt', b'12345')
        summary, store = self.run_engine(collector=FileCollector(max_file_bytes=4))
        self.assertEqual(summary['collected'], 1)
        self.assertEqual(summary['findings'], 1)
        self.assertFalse(store.diagnostics)
        self.assertFalse(store.records[0]['content_retained'])
        self.assertEqual(store.records[0]['data'], b'')
        self.assertEqual(store.records[0]['size'], 5)
        summary, store = self.run_engine(store=MemoryStore(max_bytes=4))
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(summary['collected'], 1)
        self.assertFalse(store.records[0]['content_retained'])

    def test_large_file_hash_and_keyword_still_appear(self):
        source = self.root / 'large-document.txt'
        chunk = b'x' * (1024 * 1024)
        digest = hashlib.sha256()
        with source.open('wb') as output:
            for _ in range(33):
                output.write(chunk)
                digest.update(chunk)
            output.write(b' late keyword')
            digest.update(b' late keyword')
        config = configuration('matches_only', [digest.hexdigest()], ['late keyword'],
                               hash_matches=True, file_contents=True)
        progress = []
        summary, store = self.run_engine(config, on_progress=progress.append)
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(summary['findings'], 1)
        self.assertEqual(summary['collected'], 1)
        record = store.records[0]
        self.assertEqual(record['category'], 'Documents')
        self.assertEqual(record['matches']['hashes']['sha256'], digest.hexdigest())
        self.assertEqual(record['matches']['file_contents'], ['late keyword'])
        self.assertEqual(record['data'], b'')
        self.assertEqual(store.bytes_used, 0)
        self.assertEqual(record['size'], source.stat().st_size)

    def test_memory_budget_does_not_hide_later_matches(self):
        first = self.file('first/document.txt', b'full')
        second = self.file('second/document.txt', b'match me')
        config = configuration(hashes=[hashlib.sha256(b'match me').hexdigest()],
                               keywords=['match me'], hash_matches=True, file_contents=True)
        summary, store = self.run_engine(config, store=MemoryStore(max_bytes=4),
                                        targets={'paths': [str(first.parent), str(second.parent)]})
        self.assertEqual(summary['status'], 'completed')
        self.assertEqual(summary['collected'], 2)
        self.assertEqual(summary['findings'], 2)
        self.assertEqual(store.bytes_used, 4)
        later = store.records[1]
        self.assertEqual(later['path'], str(second))
        self.assertIn('hashes', later['matches'])
        self.assertIn('file_contents', later['matches'])

    def test_streaming_keywords_cross_byte_and_character_boundaries(self):
        from analyzers.matching.keyword_matcher import KeywordMatcher
        from analyzers.matching.hash_matcher import HashMatcher
        data = 'prefix GrÜße test phrase suffix'.encode('utf-8')
        stream = KeywordMatcher(['GRÜSSE', 'test phrase', 'not present']).stream()
        hashes = HashMatcher([hashlib.md5(data, usedforsecurity=False).hexdigest()]).stream()
        for byte in data:
            chunk = bytes([byte])
            stream.update(chunk)
            hashes.update(chunk)
        self.assertEqual(stream.matches(), ['GRÜSSE', 'test phrase'])
        self.assertIn('md5', hashes.matches())

    def test_finding_record_limit_is_explicit(self):
        self.file('one.txt')
        self.file('two.txt')
        summary, store = self.run_engine(store=MemoryStore(max_records=1))
        self.assertEqual(summary['status'], 'memory_limit')
        self.assertEqual(len(store.records), 1)
        self.assertIn('finding-record limit', store.diagnostics[-1]['message'])

    def test_changed_file_is_discarded(self):
        source = self.file('changing.txt')
        original = os.fstat
        calls = 0

        def changed_stat(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                source.write_bytes(b'changed bytes')
            return original(descriptor)

        with patch('artifacts.file_collector.os.fstat', side_effect=changed_stat):
            with self.assertRaisesRegex(ValueError, 'changed during acquisition'):
                FileCollector().collect(str(source), lambda: False)

    def test_noatime_fallback_remains_read_only(self):
        import errno
        path = self.file('source.txt')
        real_open = os.open
        flags_seen = []

        def open_file(filename, flags, **kwargs):
            flags_seen.append(flags)
            if len(flags_seen) == 1:
                raise PermissionError(errno.EPERM, 'No permission for O_NOATIME')
            return real_open(filename, flags, **kwargs)

        with patch('artifacts.file_collector.os.open', side_effect=open_file):
            data, _ = FileCollector().collect(str(path), lambda: False)
        self.assertEqual(data, b'evidence')
        self.assertEqual(len(flags_seen), 2)
        self.assertTrue(all((flags & os.O_ACCMODE) == os.O_RDONLY for flags in flags_seen))

    def test_close_window_stops_worker_before_destroying_it(self):
        window = MainWindow()
        self.addCleanup(window.deleteLater)
        self.file('source.txt')
        original = FileCollector.collect

        def wait_for_cancel(collector, path, cancelled, directory_fd=None, **kwargs):
            import time
            for _ in range(200):
                if cancelled():
                    raise CollectionCancelled()
                time.sleep(0.001)
            return original(collector, path, cancelled, directory_fd, **kwargs)

        def start_and_close():
            window.target_selection = {'paths': [str(self.root)], 'acquire_ram': False}
            window.start_triage(configuration())
            window.close()
            self.assertTrue(window.close_after_scan)

        with patch.object(FileCollector, 'collect', wait_for_cancel):
            summary = self.wait_for_scan(window.scan_controller, start_and_close)
        self.assertEqual(summary['status'], 'stopped')

    def test_cancellation_keeps_partial_evidence(self):
        self.file('first.txt')
        self.file('second.txt')
        cancel = Event()
        summary, store = self.run_engine(cancel=cancel, on_finding=lambda record: cancel.set())
        self.assertEqual(summary['status'], 'stopped')
        self.assertEqual(len(store.records), 1)
        cancel.set()
        with self.assertRaises(CollectionCancelled):
            FileCollector().collect(str(self.root / 'first.txt'), cancel.is_set)

    def test_ram_request_is_separate_from_filesystem_scan(self):
        summary, store = self.run_engine(targets={'paths': [str(self.root / 'missing')], 'acquire_ram': True})
        self.assertEqual(summary['collected'], 0)
        self.assertEqual(summary['errors'], 1)
        self.assertNotEqual(store.diagnostics[0]['path'], 'RAM')
        self.file('source.txt')
        summary, _ = self.run_engine(targets={'paths': [str(self.root)], 'acquire_ram': True})
        self.assertEqual(summary['errors'], 0)
        self.assertEqual(summary['collected'], 1)
        summary, store = self.run_engine(targets={'paths': ['/proc']})
        self.assertEqual(summary['examined'], 0)
        self.assertEqual(store.diagnostics[0]['level'], 'warning')

    def test_reference_lists_excluded_and_browser_sidecars(self):
        reference = self.file('hashes.txt')
        self.file('.mozilla/firefox/profile/places.sqlite-wal')
        config = configuration()
        config['hash_files'] = [str(reference)]
        summary, store = self.run_engine(config)
        self.assertEqual(summary['collected'], 1)
        self.assertEqual(store.records[0]['category'], 'Browsers')
        self.assertEqual(category_for('/media/disk/etc/passwd'), 'User Accounts')

    def wait_for_scan(self, controller, action=None):
        loop = QEventLoop()
        summaries = []
        controller.completed.connect(summaries.append)
        controller.completed.connect(loop.quit)
        timeout = QTimer()
        timeout.setSingleShot(True)
        timeout.timeout.connect(loop.quit)
        timeout.start(5000)
        if action:
            action()
        loop.exec()
        timeout.stop()
        if controller.running:
            controller.stop()
            controller.worker.wait(5000)
            self.app.processEvents()
        self.assertTrue(summaries, 'Scan failed to complete')
        return summaries[0]

    def test_threaded_controller_and_hash_signal(self):
        self.file('matched.txt')
        controller = ScanController()
        notifications = []
        controller.hash_match.connect(notifications.append)
        config = configuration('matches_only', [hashlib.sha256(b'evidence').hexdigest()], hash_matches=True)
        summary = self.wait_for_scan(controller, lambda: controller.start({'paths': [str(self.root)]}, config))
        self.assertFalse(controller.running)
        self.assertEqual(summary['collected'], 1)
        self.assertEqual(len(notifications), 1)

    def test_live_page_navigation_and_next(self):
        self.file('picture.jpg')
        window = MainWindow()
        self.addCleanup(window.deleteLater)
        window.open(window.privileges, False)
        window.privileges.next_button.click()
        window.accept_targets({'paths': [str(self.root)], 'acquire_ram': False})
        summary = self.wait_for_scan(window.scan_controller, lambda: window.start_triage(configuration()))
        self.assertIs(window.stack.currentWidget(), window.analysis)
        self.assertEqual(summary['collected'], 1)
        self.assertEqual(window.analysis.results.topLevelItemCount(), 1)
        self.assertFalse(window.analysis.next_button.isHidden())
        self.assertTrue(window.analysis.back_button.isEnabled())
        window.analysis.next_button.click()
        self.assertIs(window.stack.currentWidget(), window.export)
        window.go_back()
        self.assertIs(window.stack.currentWidget(), window.analysis)
        window.go_back()
        self.assertIs(window.stack.currentWidget(), window.configuration)

    def test_documents_and_os_activity_update_before_scan_finishes(self):
        document = self.file('docs/test.txt', b'needle')
        activity = self.file('var/log/test.log', b'needle')
        gate = self.file('gate/wait.txt')
        window = MainWindow()
        self.addCleanup(window.deleteLater)
        release = Event()
        live_updates = []
        original = FileCollector.collect

        def collect(collector, path, cancelled, directory_fd=None, **kwargs):
            if path == str(gate):
                release.wait(2)
            return original(collector, path, cancelled, directory_fd, **kwargs)

        def check_live(record):
            if {'Documents', 'OS Activity'} <= window.analysis.categories.keys():
                live_updates.append(window.scan_controller.running)
                self.assertFalse(window.analysis.categories['Documents'].isExpanded())
                self.assertFalse(window.analysis.categories['OS Activity'].isExpanded())
                release.set()

        window.scan_controller.finding.connect(check_live)
        window.scan_controller.hash_match.disconnect(window.analysis.notify_hash_match)
        window.target_selection = {'paths': [str(document.parent), str(activity.parent), str(gate.parent)]}
        config = configuration('matches_only', [hashlib.sha256(b'needle').hexdigest()],
                               ['needle'], hash_matches=True, file_contents=True)
        with patch.object(FileCollector, 'collect', collect):
            summary = self.wait_for_scan(window.scan_controller, lambda: window.start_triage(config))
        self.assertEqual(summary['findings'], 2)
        self.assertEqual(live_updates, [True])
        self.assertIn('Hash Matches', window.analysis.categories)
        self.assertIn('File Content Matches', window.analysis.categories)

    def test_missing_source_media_preview_is_explained(self):
        dialog = MediaPreview({'path': '/large.mp4', 'category': 'Videos', 'data': b'',
                               'content_retained': False, 'retention_reason': 'Per-file RAM retention limit exceeded.'})
        self.assertIsNone(dialog.player)
        self.assertIn('Cannot open this target file', dialog.error.text())
        dialog.close()

    def test_uncached_source_file_can_be_read_completely(self):
        from storage.source_file import open_record_device
        content = b'complete target file' * 6000
        self.file('large.txt', content)
        summary, store = self.run_engine(collector=FileCollector(max_file_bytes=4))
        record = store.records[0]
        self.assertFalse(record['content_retained'])
        device, description = open_record_device(record)
        self.assertIn('source file', description)
        self.assertEqual(bytes(device.readAll()), content)
        device.close()
        self.assertEqual(summary['collected'], 1)

    def test_paged_view_reaches_end_of_uncached_target_file(self):
        from interface.widgets.file_details import FileDetails
        content = b'x' * (64 * 1024) + b'last page visible'
        self.file('large.txt', content)
        _, store = self.run_engine(collector=FileCollector(max_file_bytes=4))
        dialog = FileDetails(store.records[0])
        self.assertTrue(dialog.next.isEnabled())
        dialog.next.click()
        self.assertEqual(dialog.text.toPlainText(), 'last page visible')
        self.assertFalse(dialog.next.isEnabled())
        self.assertTrue(dialog.previous.isEnabled())
        dialog.close()

    def test_uncached_picture_preview_uses_source_file(self):
        image = QImage(8, 8, QImage.Format.Format_RGB32)
        image.fill(0xff223344)
        path = self.root / 'source.png'
        self.assertTrue(image.save(str(path)))
        _, store = self.run_engine(collector=FileCollector(max_file_bytes=4))
        dialog = MediaPreview(store.records[0])
        self.assertFalse(dialog.error.text())
        self.assertFalse(store.records[0]['content_retained'])
        dialog.close()

    def test_changed_source_file_is_not_shown_as_original(self):
        from storage.source_file import open_record_device
        path = self.file('source.txt')
        _, store = self.run_engine(collector=FileCollector(max_file_bytes=4))
        path.write_bytes(b'replaced after the scan')
        with self.assertRaisesRegex(ValueError, 'changed or was replaced'):
            open_record_device(store.records[0])

    def test_imported_file_hashes_reach_live_category_and_notification(self):
        import subprocess
        window = MainWindow()
        self.addCleanup(window.deleteLater)
        source = self.file('targets/test.txt', b'needle\n')
        reference = self.root / 'sha256.txt'
        reference.write_bytes(subprocess.check_output(['sha256sum', str(source)]))
        keywords = self.file('keywords.txt', b'needle\n')
        window.welcome.quick_triage.emit()
        window.privileges.next_button.click()
        window.accept_targets({'paths': [str(source.parent)], 'acquire_ram': False})
        page = window.configuration
        page.hash_lists.add_files([str(reference)])
        page.keyword_lists.add_files([str(keywords)])
        self.assertFalse(page.hash_lists.error.text())
        summary = self.wait_for_scan(window.scan_controller, page.submit)
        self.assertEqual(summary['hash_checked'], 1)
        self.assertEqual(summary['hash_matches'], 1)
        self.assertIn('Hash Matches', window.analysis.categories)
        self.assertIsNotNone(window.analysis.notification)
        self.assertEqual(window.analysis.notification.text(), str(source))
        self.assertIn('complete source file', window.analysis.notification.informativeText())
        window.analysis.notification.accept()

    def test_different_newline_means_different_hash(self):
        self.file('source.txt', b'needle\n')
        config = configuration(hashes=[hashlib.sha256(b'needle').hexdigest()], keywords=['needle'],
                               hash_matches=True, file_contents=True)
        summary, store = self.run_engine(config)
        self.assertEqual(summary['hash_checked'], 1)
        self.assertEqual(summary['hash_matches'], 0)
        self.assertIn('file_contents', store.records[0]['matches'])
        self.assertEqual(store.records[0]['calculated_hashes']['sha256'], hashlib.sha256(b'needle\n').hexdigest())

    def test_hash_calculation_against_all_four_system_tools(self):
        import subprocess
        from controllers.configuration_controller import ConfigurationController
        tools = {'md5': 'md5sum', 'sha1': 'sha1sum', 'sha256': 'sha256sum', 'sha512': 'sha512sum'}
        inputs = [b'', b'abc', bytes(range(256)) * 8193 + b'\x00\r\nfinal chunk']
        for index, data in enumerate(inputs):
            source = self.file(f'case-{index}/file.bin', data)
            for algorithm, tool in tools.items():
                with self.subTest(input=index, algorithm=algorithm):
                    output = subprocess.check_output([tool, str(source)]).decode()
                    expected = output.split()[0]
                    reference = self.file(f'references-{index}/{algorithm}.txt', output.upper().encode())
                    options = dict(folder_names=False, file_names=False, file_contents=False, hash_matches=True)
                    config = ConfigurationController().prepare([str(reference)], [], options, 'matches_only')
                    summary, store = self.run_engine(config, targets={'paths': [str(source.parent)]})
                    self.assertEqual(summary['hash_checked'], 1)
                    self.assertEqual(summary['hash_matches'], 1)
                    self.assertEqual(store.records[0]['matches']['hashes'], {algorithm: expected})
                    self.assertEqual(store.records[0]['calculated_hashes'][algorithm], expected)
                    self.assertIn('1 matching files', store.diagnostics[-1]['message'])

    def test_hash_mismatch_details_show_calculated_digest(self):
        from interface.widgets.file_details import FileDetails
        self.file('source.txt', b'needle\n')
        config = configuration(hashes=[hashlib.sha256(b'needle').hexdigest()], hash_matches=True)
        _, store = self.run_engine(config)
        dialog = FileDetails(store.records[0], hash_configuration=config)
        self.assertIn('NO MATCH', dialog.details.toPlainText())
        self.assertIn(hashlib.sha256(b'needle\n').hexdigest(), dialog.details.toPlainText())
        dialog.close()

    def test_categories_stay_collapsed_until_clicked(self):
        from PySide6.QtCore import Qt, QPoint, QPointF, QEvent
        from PySide6.QtGui import QMouseEvent
        from interface.pages.analysis import AnalysisPage
        page = AnalysisPage()
        page.resize(960, 640)
        page.show()
        record = {'category': 'Documents', 'path': '/test/source.txt', 'kind': 'file',
                  'id': 0, 'size': 10, 'matches': {}, 'collection': 'verified source file'}
        page.add_finding(record)
        self.app.processEvents()
        category = page.categories['Documents']
        self.assertFalse(category.isExpanded())
        self.assertTrue(page.results.visualItemRect(category.child(0)).isEmpty())
        bounds = page.results.visualItemRect(category)
        point = QPoint(bounds.left() + 100, bounds.center().y())

        def click():
            viewport = page.results.viewport()
            for event_type, buttons in ((QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton),
                                        (QEvent.Type.MouseButtonRelease, Qt.MouseButton.NoButton)):
                event = QMouseEvent(event_type, QPointF(point), QPointF(viewport.mapToGlobal(point)),
                                    Qt.MouseButton.LeftButton, buttons, Qt.KeyboardModifier.NoModifier)
                self.app.sendEvent(viewport, event)

        click()
        self.assertTrue(category.isExpanded())
        self.assertFalse(page.results.visualItemRect(category.child(0)).isEmpty())
        page.add_finding(dict(record, id=1, path='/test/second.txt'))
        self.assertTrue(category.isExpanded())
        click()
        self.assertFalse(category.isExpanded())
        page.add_finding(dict(record, id=2, path='/test/third.txt'))
        self.assertFalse(category.isExpanded())
        page.close()
        page.deleteLater()

    def test_image_preview_uses_acquired_bytes(self):
        image = QImage(8, 8, QImage.Format.Format_RGB32)
        image.fill(0xff112233)
        buffer = QBuffer()
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        self.assertTrue(image.save(buffer, 'PNG'))
        dialog = MediaPreview({'path': '/missing-source.png', 'category': 'Pictures',
                               'data': bytes(buffer.data())})
        self.assertFalse(dialog.error.text())
        self.assertEqual(bytes(dialog.buffer.data()), bytes(buffer.data()))
        dialog.close()

    def test_hash_notification_queue(self):
        from interface.pages.analysis import AnalysisPage
        page = AnalysisPage()
        page.begin()
        for index in range(2):
            page.notify_hash_match({'path': f'/test/{index}', 'matches': {'hashes': {'sha256': 'a' * 64}}})
        self.assertIsNotNone(page.notification)
        self.assertEqual(len(page.hash_notifications), 1)
        page.notification.accept()
        self.app.processEvents()
        self.assertEqual(page.notification.text(), '/test/1')
        page.hash_notifications.clear()
        page.notification.accept()
        page.timer.stop()
        page.deleteLater()
