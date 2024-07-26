from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework import status
import requests
from django.http import JsonResponse
from .models import Vulnerability
import json
from collections import defaultdict, Counter
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth.models import User
from .serializers import UserSerializer
from django.views.decorators.csrf import csrf_exempt


class VulnerabilityViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        response = requests.get(url)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            # Pagina los datos
            paginator = VulnerabilityPagination()
            paginated_vulnerabilities = paginator.paginate_queryset(vulnerabilities, request)
            
            return paginator.get_paginated_response(paginated_vulnerabilities)
        else:
            return Response({"error": "Unable to fetch data from NVD"}, status=response.status_code)
        
class VulnerabilityPagination(PageNumberPagination):
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'count': self.page.paginator.count,
            'next': self.get_next_link(),
            'vulnerabilities': data
        })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_vulnerability(request):
    data = json.loads(request.body)
    id_cv = data.get('vul_id')
    
    if not id_cv:
        return JsonResponse({'status': 'error', 'message': 'vul_id not provided'}, status=400)
    
    response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0')
    if response.status_code != 200:
        return JsonResponse({'status': 'error', 'message': 'Failed to fetch data from NVD API'}, status=500)

    vulnerabilities_data = response.json().get('vulnerabilities', [])
    vul_id = None
    for vulnerability in vulnerabilities_data:
        cve = vulnerability.get('cve', {})
        if cve.get('id') == id_cv:
            vul_id = cve.get('id')
            vulnStatus = 'FIXED'
            try:
                existing_vulnerability = Vulnerability.objects.get(vul_id=id_cv)
                existing_vulnerability.vulnStatus = vulnStatus
                existing_vulnerability.save()
            except Vulnerability.DoesNotExist:
                Vulnerability.objects.create(vul_id=vul_id, vulnStatus=vulnStatus)
            
            response_data = {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": vul_id,
                            "vulnStatus": vulnStatus,
                            "descriptions": cve.get('descriptions', [])
                        }
                    }
                ]
            }
            return JsonResponse(response_data)
    
    return JsonResponse({'status': 'error', 'message': 'Vulnerability not found'}, status=404)

@csrf_exempt
def register_user(request):
    data = json.loads(request.body)
    serializer = UserSerializer(data=data)
    
    if serializer.is_valid():
        user = serializer.save()
        return JsonResponse({'status': 'success', 'message': 'User created successfully', 'user': serializer.data}, status=201)
    return JsonResponse({'status': 'error', 'message': serializer.errors}, status=400)

@csrf_exempt
def list_vulnerabilities(request):
    response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0')
    if response.status_code != 200:
        return JsonResponse({'status': 'error', 'message': 'Failed to fetch data from NVD API'}, status=500)

    nvd_vulnerabilities = response.json().get('vulnerabilities', [])
    fixed_ids = Vulnerability.objects.filter(vulnStatus='FIXED').values_list('vul_id', flat=True)
    
    filtered_vulnerabilities = [
        vuln for vuln in nvd_vulnerabilities
        if vuln.get('cve', {}).get('id') not in fixed_ids
    ]
    
    response_data = {"vulnerabilities": filtered_vulnerabilities}
    return JsonResponse(response_data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def summarize_by_severity(request):
    try:
        response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0')
        response.raise_for_status()
    except requests.RequestException as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    nvd_vulnerabilities = response.json().get('vulnerabilities', [])

    severity_counts = defaultdict(Counter)

    for vuln in nvd_vulnerabilities:
        cve = vuln.get('cve', {})
        metrics = cve.get('metrics', {})

        for metric_type, metric_list in metrics.items():
            for metric in metric_list:
                base_severity = None
                
                for key in ['baseSeverity', 'cvssData']:
                    if key in metric:
                        if key == 'cvssData':
                            base_severity = metric[key].get('baseSeverity', 'UNKNOWN')
                        else:
                            base_severity = metric.get('baseSeverity', 'UNKNOWN')
                        break

                if not base_severity:
                    base_severity = 'UNKNOWN'

                severity_counts[metric_type][base_severity] += 1

    response_data = {metric_type: [{"severity": severity, "count": count} for severity, count in counts.items()] for metric_type, counts in severity_counts.items()}

    return JsonResponse(response_data, safe=False)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def count_metrics_types(request):
    try:
        response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0', params={'resultsPerPage': 2000})
        response.raise_for_status()
    except requests.RequestException as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    data = response.json()
    vulnerabilities = data.get('vulnerabilities', [])

    metrics_types = set()

    for vuln in vulnerabilities:
        metrics = vuln.get('cve', {}).get('metrics', {})
        for metric_type in metrics.keys():
            metrics_types.add(metric_type)

    return JsonResponse({'metricsTypes': list(metrics_types)}, safe=False)
