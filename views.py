"""
ACME Store - Django Worker Service
Uses: Django==3.2.12 (CVE-2022-28346 - SQL injection in QuerySet.annotate())
      Pillow==9.0.0 (CVE-2022-22817 - command injection via ImageMath.eval())
      requests==2.27.0 (CVE-2023-32681 - proxy auth header leakage)
      pyyaml==5.4.1 (CVE-2020-14343 - arbitrary code execution via yaml.load())
"""

from django.db import models
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import Count, Sum, Avg

import requests
import PIL.Image
import PIL.ImageOps
import io
import yaml
import logging
import os

logger = logging.getLogger(__name__)

ANALYTICS_SERVICE_URL = os.environ.get('ANALYTICS_SERVICE_URL', 'http://analytics-svc:5001')
PROXY_CONFIG = os.environ.get('HTTP_PROXY', '')


# ─── MODELS ───────────────────────────────────────────────────────────────────

class Order(models.Model):
    order_id = models.UUIDField()
    user_id = models.IntegerField()
    total = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        app_label = 'store'


class Product(models.Model):
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock = models.IntegerField(default=0)

    class Meta:
        app_label = 'store'


# ─── VIEWS ────────────────────────────────────────────────────────────────────

@method_decorator(csrf_exempt, name='dispatch')
class ReportsView(View):
    """
    ⚠ VULNERABLE: CVE-2022-28346
    QuerySet.annotate() called with **request.GET.dict()
    User GET params become annotation aliases → SQL injection
    """

    def get(self, request):
        # ⚠ HIGHLY VULNERABLE: user GET params directly into annotate()
        # e.g. GET /reports/?evil_alias=INJECTED_SQL
        try:
            user_params = request.GET.dict()
            # This is the vulnerable pattern from CVE-2022-28346
            queryset = Order.objects.values('status').annotate(
                count=Count('id'),
                **user_params   # ← user-controlled aliases
            )
            data = list(queryset)
            return JsonResponse({'reports': data})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class SafeReportsView(View):
    """
    SAFE version of reports — hardcoded annotations only
    AI should detect this as NOT vulnerable (no user input to annotate)
    """

    def get(self, request):
        # SAFE: hardcoded annotation keys, no user input
        queryset = Order.objects.values('status').annotate(
            count=Count('id'),
            total_value=Sum('total'),
            avg_value=Avg('total')
        )
        data = list(queryset)
        return JsonResponse({'reports': data})


@method_decorator(csrf_exempt, name='dispatch')
class ImageProcessView(View):
    """
    Image processing endpoint
    Uses Pillow for thumbnail generation (SAFE usage)
    Does NOT use PIL.ImageMath.eval() → CVE-2022-22817 NOT reachable
    """

    def post(self, request):
        if 'image' not in request.FILES:
            return JsonResponse({'error': 'No image provided'}, status=400)

        image_file = request.FILES['image']

        try:
            img = PIL.Image.open(image_file)

            # SAFE: only uses Image.thumbnail() and Image.save()
            # CVE-2022-22817 only applies to PIL.ImageMath.eval() — NOT called here
            img.thumbnail((300, 300), PIL.Image.LANCZOS)

            # Convert to RGB if needed (safe operation)
            if img.mode in ('RGBA', 'P'):
                img = img.convert('RGB')

            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=85)

            return JsonResponse({
                'success': True,
                'size': buffer.tell(),
                'dimensions': img.size
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
class ExternalFetchView(View):
    """
    Fetches data from analytics service
    Uses requests with proxy config
    ⚠ UNCERTAIN: CVE-2023-32681 proxy auth header leakage
    proxy config comes from environment variable — depends on what's configured
    """

    def get(self, request):
        try:
            proxies = {'https': PROXY_CONFIG} if PROXY_CONFIG else None

            # ⚠ UNCERTAIN: if PROXY_CONFIG is set and service redirects to external URL,
            # proxy-authorization headers could leak. Depends on deployment configuration.
            response = requests.get(
                f'{ANALYTICS_SERVICE_URL}/metrics',
                proxies=proxies,
                timeout=5,
                headers={'X-Internal-Token': os.environ.get('INTERNAL_TOKEN', '')}
            )
            return JsonResponse(response.json())
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=502)


@method_decorator(csrf_exempt, name='dispatch')
class ConfigLoaderView(View):
    """
    ⚠ VULNERABLE: pyyaml@5.4.1 (CVE-2020-14343)
    yaml.load() without Loader=yaml.SafeLoader → arbitrary code execution
    User-supplied YAML is parsed unsafely
    """

    def post(self, request):
        yaml_content = request.body.decode('utf-8')

        try:
            # ⚠ VULNERABLE: yaml.load() without SafeLoader
            # Attacker can execute arbitrary Python: !!python/object/apply:os.system ['rm -rf /']
            config = yaml.load(yaml_content)  # noqa: S506
            return JsonResponse({'config': config, 'parsed': True})
        except yaml.YAMLError as e:
            return JsonResponse({'error': str(e)}, status=400)


@method_decorator(csrf_exempt, name='dispatch')
class SafeConfigLoaderView(View):
    """
    SAFE version: uses yaml.safe_load()
    AI should detect this as NOT vulnerable to CVE-2020-14343
    """

    def post(self, request):
        yaml_content = request.body.decode('utf-8')
        try:
            # SAFE: SafeLoader prevents arbitrary code execution
            config = yaml.safe_load(yaml_content)
            return JsonResponse({'config': config, 'parsed': True})
        except yaml.YAMLError as e:
            return JsonResponse({'error': str(e)}, status=400)
