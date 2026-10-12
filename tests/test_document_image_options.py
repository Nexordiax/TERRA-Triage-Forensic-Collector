"""Document image searches require explicit opt-in, independently of pictures."""
import hashlib
import io
import unittest
import zipfile
from unittest.mock import patch

from PIL import Image
from PySide6.QtWidgets import QApplication

from analyzers.content import eligible
from analyzers.content_worker import analyze
from interface.pages.configuration import ConfigurationPage
from interface.widgets.content_options import ContentOptions
from tests.test_content_analysis import text_pdf
from tests.test_scan import configuration


class DocumentImageOptionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    @staticmethod
    def picture(format='PNG'):
        output = io.BytesIO()
        with Image.new('RGB', (40, 40), (180, 120, 90)) as image:
            image.save(output, format)
        return output.getvalue()

    @staticmethod
    def archive(members):
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for name, data in members.items():
                archive.writestr(name, data)
        return output.getvalue()

    def test_gui_default_and_pdf_controls_require_opt_in(self):
        controls = ContentOptions()
        self.assertFalse(controls.values()['document_images'])
        self.assertTrue(controls.ocr.isChecked())
        self.assertTrue(controls.skin.isChecked())
        self.assertFalse(controls.ocr_pdf.isChecked())
        controls.document_images.setChecked(True)
        self.assertTrue(controls.values()['document_images'])
        self.assertTrue(controls.ocr_pdf.isEnabled())
        controls.ocr_pdf.setChecked(True)
        self.assertTrue(controls.ocr_all_pages.isEnabled())
        controls.document_images.setChecked(False)
        self.assertFalse(controls.ocr_all_pages.isChecked())
        self.assertFalse(controls.ocr_pdf.isChecked())
        controls.deleteLater()

    def test_pdf_visual_search_and_inventory_are_skipped_without_opt_in(self):
        options = dict(ocr=True, ocr_pdf=True, ocr_all_pdf_pages=True, skin_tone=True,
                       weapon_detection=True, image_references=[{}], _inventory_embedded=True)
        self.assertFalse(eligible('document.pdf', options))
        with patch('analyzers.ocr.analyzer.recognize') as ocr, patch('analyzers.image_classification.analyzer.screen_selected') as skin:
            result = analyze(self.picture('PDF'), '.pdf', options)
        self.assertEqual(result['entries'], [])
        self.assertEqual(result['limitations'], [])
        ocr.assert_not_called()
        skin.assert_not_called()
        self.assertTrue(eligible('document.pdf', dict(options, document_images=True)))
        self.assertTrue(eligible('image.png', options))

    def test_office_skips_image_decoding_but_keeps_nested_hashes_and_stored_text(self):
        picture = self.picture()
        nested = self.archive({'photo.png': picture})
        document = self.archive({'word/media/photo.png': picture, 'nested.zip': nested,
                                 'word/document.xml': '<w:document xmlns:w="word"><w:p><w:r><w:t>stored evidence</w:t></w:r></w:p></w:document>'})
        options = dict(ocr=True, skin_tone=True, weapon_detection=True, extract_documents=True,
                       container_hashes=[hashlib.md5(picture).hexdigest()])
        with patch('analyzers.ocr.analyzer.recognize') as ocr, patch('analyzers.image_classification.analyzer.screen_selected') as skin:
            result = analyze(document, '.docx', options)
        ocr.assert_not_called()
        skin.assert_not_called()
        self.assertEqual(sum(bool(row.get('matched_hashes')) for row in result['entries']), 2)
        self.assertTrue(any(row['type'] == 'document_text' for row in result['entries']))
        self.assertFalse(any(row['type'] == 'embedded_image' for row in result['entries']))

    def test_stored_pdf_text_and_archived_pictures_remain_available(self):
        result = analyze(text_pdf(), '.pdf', {'extract_documents': True, 'ocr': True, 'skin_tone': True})
        self.assertEqual([row['type'] for row in result['entries']], ['document_text'])
        result = analyze(self.archive({'picture.png': self.picture()}), '.zip', {'skin_tone': True})
        self.assertTrue(any(row['type'] == 'skin_colour_screen' for row in result['entries']))

    def test_configuration_restores_document_image_selection_for_back_navigation(self):
        page = ConfigurationPage()
        config = configuration()
        config['analysis_options'] = dict(document_images=True, ocr=True, ocr_pdf=True)
        page.restore_values(config, {'paths': ['/tmp'], 'acquire_ram': False})
        self.assertTrue(page.content_analysis.document_images.isChecked())
        self.assertTrue(page.content_analysis.ocr_pdf.isEnabled())
        config['analysis_options'] = {}
        page.restore_values(config, {'paths': ['/tmp'], 'acquire_ram': False})
        self.assertFalse(page.content_analysis.document_images.isChecked())
        page.deleteLater()
