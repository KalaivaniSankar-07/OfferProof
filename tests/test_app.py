import io
import tempfile
import unittest
from pathlib import Path
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject
import app as application
from services.pdf_analyzer import extract_pdf_text
from services.risk_engine import analyze_offer


def pdf_bytes(text=None, pages=1):
    writer = PdfWriter()
    for _ in range(pages):
        page = writer.add_blank_page(width=612, height=792)
        if text:
            font = DictionaryObject({NameObject('/Type'): NameObject('/Font'),
                                     NameObject('/Subtype'): NameObject('/Type1'),
                                     NameObject('/BaseFont'): NameObject('/Helvetica')})
            page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'): DictionaryObject({NameObject('/F1'): writer._add_object(font)})})
            stream = DecodedStreamObject()
            stream.set_data(f'BT /F1 12 Tf 50 700 Td ({text}) Tj ET'.encode())
            page[NameObject('/Contents')] = writer._add_object(stream)
    output = io.BytesIO()
    writer.write(output)
    output.seek(0)
    return output


class OfferProofTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old_db = application.DB_NAME
        application.DB_NAME = str(Path(self.directory.name) / 'test.db')
        application.app.config['TESTING'] = True
        application.init_db()
        self.client = application.app.test_client()

    def tearDown(self):
        application.DB_NAME = self.old_db
        self.directory.cleanup()

    def test_pages_and_stylesheet(self):
        for path in ['/', '/verify', '/report', '/dashboard', '/history', '/static/css/style.css']:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                response.close()

    def test_verification_history_and_masks(self):
        response = self.client.post('/analyze', data={'company': 'Synthetic Test', 'email': 'person@example.com', 'phone': '9876543210', 'message': 'Pay now registration fee security deposit INR 5000 guaranteed job'})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'HIGH RISK', response.data)
        history = self.client.get('/history').data
        self.assertIn(b'Synthetic Test', history)
        self.assertNotIn(b'person@example.com', history)
        self.assertNotIn(b'9876543210', history)
        self.assertIn(b'p****n@example.com', history)

    def test_repeat_reports_and_invalid_loss(self):
        response = self.client.post('/report', data={'company':'Synthetic', 'email':'test@example.com', 'victim':'yes', 'amount_lost':'nan'})
        self.assertEqual(response.status_code, 302)
        with application.get_db() as db:
            row = db.execute('SELECT * FROM scam_reports').fetchone()
            self.assertEqual(row['amount_lost'], 0)
            self.assertNotEqual(row['email_fp'], 'test@example.com')
        self.assertEqual(self.client.post('/analyze', data={'email':'test@example.com'}).status_code, 200)
        with application.get_db() as db:
            self.assertEqual(db.execute('SELECT previous_reports FROM verification_history').fetchone()[0], 1)

    def test_text_pdf_is_analyzed(self):
        response = self.client.post('/analyze', data={'offer_pdf': (pdf_bytes('registration fee security deposit pay now guaranteed job INR 5000'), 'offer.pdf')})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'HIGH RISK', response.data)

    def test_pdf_failures_are_visible(self):
        for content in [io.BytesIO(b'not a pdf'), pdf_bytes()]:
            response = self.client.post('/analyze', data={'message':'registration fee pay now', 'offer_pdf':(content,'offer.pdf')})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'other submitted details were checked', response.data.lower())
            self.assertIn(b'registration fee', response.data)

    def test_pdf_limits(self):
        with self.assertRaises(ValueError):
            extract_pdf_text(pdf_bytes(pages=21))
        response = self.client.post('/analyze', data={'message':'a' * (5 * 1024 * 1024)})
        self.assertEqual(response.status_code, 413)

    def test_domain_port_and_suffix_boundary(self):
        same = analyze_offer('', 'hr@example.com', '', 'https://example.com:443', '', '')
        different = analyze_offer('', 'hr@example.com', '', 'https://notexample.com', '', '')
        self.assertFalse(any('does not match' in r for r in same['reasons']))
        self.assertTrue(any('does not match' in r for r in different['reasons']))

    def test_init_is_non_destructive(self):
        self.client.post('/analyze', data={'company':'Synthetic'})
        application.init_db()
        with application.get_db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM verification_history').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
