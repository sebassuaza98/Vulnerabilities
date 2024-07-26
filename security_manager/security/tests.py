from django.test import TestCase, Client
from django.urls import reverse
from unittest.mock import patch
import json
from .models import Vulnerability

class VulnerabilityViewsTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.add_vulnerability_url = reverse('update-vulnerability')
        self.list_vulnerabilities_url = reverse('list-vulnerabilities')
        self.summarize_by_severity_url = reverse('summarize-by-severity')
        
        # Crear un usuario y obtener un token
        self.user_data = {
            "username": "testuser",
            "password": "testpass123"
        }
        self.client.post(reverse('register_user'), self.user_data, content_type='application/json')
        
        response = self.client.post(reverse('token_obtain_pair'), self.user_data, content_type='application/json')
        self.token = response.data['access']
        self.client.defaults['HTTP_AUTHORIZATION'] = 'Bearer ' + self.token

    @patch('requests.get')
    def test_list_vulnerabilities_success(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {'vulnerabilities': []}

        response = self.client.get(self.list_vulnerabilities_url)
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(response.content, {"vulnerabilities": []})

    @patch('requests.get')
    def test_add_vulnerability_success(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'vulnerabilities': [{'cve': {'id': 'CVE-2021-1234', 'descriptions': []}}]
        }

        response = self.client.post(
            self.add_vulnerability_url,
            data=json.dumps({'vul_id': 'CVE-2021-1234'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertJSONEqual(
            response.content,
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2021-1234",
                            "vulnStatus": "FIXED",
                            "descriptions": []
                        }
                    }
                ]
            }
        )
        self.assertTrue(Vulnerability.objects.filter(vul_id='CVE-2021-1234').exists())

    @patch('requests.get')
    def test_add_vulnerability_failure(self, mock_get):
        mock_get.return_value.status_code = 500

        response = self.client.post(
            self.add_vulnerability_url,
            data=json.dumps({'vul_id': 'CVE-2021-1234'}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 500)
        self.assertJSONEqual(response.content, {'status': 'error', 'message': 'Failed to fetch data from NVD API'})
