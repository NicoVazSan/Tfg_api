import secrets
import bcrypt
import json

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from .models import Foro, CustomUser, UserSession, Ruta, Ubicacion

@csrf_exempt
def login_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'HTTP method unsupported'}, status=405)

    body = json.loads(request.body)
    username = body.get('username')
    password = body.get('password')

    if not username or not password:
        return JsonResponse({'error': 'Missing fields'}, status=400)

    try:
        user = CustomUser.objects.get(username=username)
    except CustomUser.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    if bcrypt.checkpw(password.encode(), user.encrypted_password.encode()):
        token = secrets.token_hex(10)
        UserSession.objects.create(user=user, token=token)
        return JsonResponse({'token': token}, status=200)

    return JsonResponse({'error': 'Invalid password'}, status=401)

@csrf_exempt
def register_user(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'HTTP method unsupported'}, status=405)

    body = json.loads(request.body)
    username = body.get('username')
    password = body.get('password')

    if not username or not password:
        return JsonResponse({'error': 'Missing fields'}, status=400)

    if CustomUser.objects.filter(username=username).exists():
        return JsonResponse({'error': 'User already exists'}, status=409)

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    CustomUser.objects.create(
        username=username,
        encrypted_password=hashed.decode()
    )

    return JsonResponse({'message': 'User created'}, status=201)