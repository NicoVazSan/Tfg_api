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


@csrf_exempt
def rutas(request, id_foro):
    # GET -> listar rutas de un foro
    if request.method == 'GET':

        try:
            foro = Foro.objects.get(id=id_foro)
        except Foro.DoesNotExist:
            return JsonResponse({"error": "Foro no encontrado"}, status=404)

        rutas = Ruta.objects.filter(foro=foro).order_by('-datetime')

        data = []

        for ruta in rutas:

            ubicaciones = Ubicacion.objects.filter(ruta=ruta)

            data.append({
                "id": ruta.id,
                "message": ruta.message,
                "datetime": ruta.datetime.isoformat(),
                "username": ruta.user.username,
                "ubicaciones": [
                    {
                        "id": u.id,
                        "ubi": u.ubi
                    }
                    for u in ubicaciones
                ]
            })

        return JsonResponse({
            "foro": foro.titulo,
            "rutas": data
        }, status=200)

    # POST -> crear ruta
    elif request.method == 'POST':

        # Token obligatorio
        token = request.headers.get('Authorization')

        if not token:
            return JsonResponse({"error": "Token requerido"}, status=401)

        try:
            session = UserSession.objects.get(token=token)
            usuario = session.user
        except UserSession.DoesNotExist:
            return JsonResponse({"error": "Token inválido"}, status=401)

        try:
            foro = Foro.objects.get(id=id_foro)
        except Foro.DoesNotExist:
            return JsonResponse({"error": "Foro no encontrado"}, status=404)

        try:
            body_json = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "JSON inválido"}, status=400)

        message = body_json.get('message')
        ubicaciones = body_json.get('ubicaciones', [])

        if not message:
            return JsonResponse({"error": "Message requerido"}, status=400)

        nueva_ruta = Ruta.objects.create(
            message=message,
            user=usuario,
            foro=foro
        )

        for ubi in ubicaciones:
            Ubicacion.objects.create(
                ubi=ubi,
                ruta=nueva_ruta
            )

        return JsonResponse({
            "id": nueva_ruta.id,
            "message": nueva_ruta.message,
            "datetime": nueva_ruta.datetime.isoformat(),
            "username": nueva_ruta.user.username,
            "ubicaciones": ubicaciones
        }, status=201)

    return JsonResponse({"error": "HTTP method unsupported"}, status=405)

@csrf_exempt
def ruta_detail(request, id_foro, id_ruta):

    try:
        ruta = Ruta.objects.get(id=id_ruta, foro_id=id_foro)
    except Ruta.DoesNotExist:
        return JsonResponse({"error": "Ruta no encontrada"}, status=404)

    # =========================
    # GET
    # =========================
    if request.method == 'GET':

        ubicaciones = Ubicacion.objects.filter(ruta=ruta)

        return JsonResponse({
            "id": ruta.id,
            "message": ruta.message,
            "datetime": ruta.datetime.isoformat(),
            "username": ruta.user.username,
            "foro": {
                "id": ruta.foro.id,
                "titulo": ruta.foro.titulo
            },
            "ubicaciones": [
                {
                    "id": u.id,
                    "ubi": u.ubi
                }
                for u in ubicaciones
            ]
        }, status=200)

    # =========================
    # PUT
    # =========================
    elif request.method == 'PUT':

        token = request.headers.get('Authorization')

        if not token:
            return JsonResponse({"error": "Token requerido"}, status=401)

        try:
            session = UserSession.objects.get(token=token)
        except UserSession.DoesNotExist:
            return JsonResponse({"error": "Token inválido"}, status=401)

        if ruta.user != session.user:
            return JsonResponse({"error": "No autorizado"}, status=403)

        try:
            body_json = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "JSON inválido"}, status=400)

        new_message = body_json.get('message')
        nuevas_ubicaciones = body_json.get('ubicaciones')

        if new_message:
            ruta.message = new_message

        ruta.save()

        if nuevas_ubicaciones is not None:
            Ubicacion.objects.filter(ruta=ruta).delete()

            for ubi in nuevas_ubicaciones:
                Ubicacion.objects.create(
                    ubi=ubi,
                    ruta=ruta
                )

        ubicaciones = Ubicacion.objects.filter(ruta=ruta)

        return JsonResponse({
            "message": "Ruta actualizada",
            "ruta": {
                "id": ruta.id,
                "message": ruta.message,
                "datetime": ruta.datetime.isoformat(),
                "username": ruta.user.username,
                "ubicaciones": [
                    {
                        "id": u.id,
                        "ubi": u.ubi
                    }
                    for u in ubicaciones
                ]
            }
        }, status=200)

    # =========================
    # DELETE
    # =========================
    elif request.method == 'DELETE':

        token = request.headers.get('Authorization')

        if not token:
            return JsonResponse({"error": "Token requerido"}, status=401)

        try:
            session = UserSession.objects.get(token=token)
        except UserSession.DoesNotExist:
            return JsonResponse({"error": "Token inválido"}, status=401)

        if ruta.user != session.user:
            return JsonResponse({"error": "No autorizado"}, status=403)

        ruta.delete()

        return JsonResponse({"message": "Ruta eliminada"}, status=200)

    return JsonResponse({"error": "HTTP method unsupported"}, status=405)

@csrf_exempt
def foros(request):

    # =========================
    # GET
    # =========================
    if request.method == 'GET':

        foros = Foro.objects.all()

        data = []

        for foro in foros:
            data.append({
                "id": foro.id,
                "titulo": foro.titulo,
                "contenido": foro.contenido
            })

        return JsonResponse({
            "foros": data
        }, status=200)

    # =========================
    # POST
    # =========================
    elif request.method == 'POST':

        try:
            body_json = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'JSON inválido'}, status=400)

        titulo = body_json.get('titulo')
        contenido = body_json.get('contenido')

        if not titulo or not contenido:
            return JsonResponse({
                'error': 'Se requiere título y contenido'
            }, status=400)

        nuevo_foro = Foro.objects.create(
            titulo=titulo,
            contenido=contenido
        )

        return JsonResponse({
            "id": nuevo_foro.id,
            "titulo": nuevo_foro.titulo,
            "contenido": nuevo_foro.contenido
        }, status=201)

    return JsonResponse({
        'error': 'HTTP method unsupported'
    }, status=405)

@csrf_exempt
def foro_detail(request, id_foro):

    try:
        foro = Foro.objects.get(id=id_foro)
    except Foro.DoesNotExist:
        return JsonResponse({
            "error": "Foro no encontrado"
        }, status=404)

    # =========================
    # GET
    # =========================
    if request.method == 'GET':

        return JsonResponse({
            "id": foro.id,
            "titulo": foro.titulo,
            "contenido": foro.contenido
        }, status=200)

    # =========================
    # PUT
    # =========================
    elif request.method == 'PUT':

        try:
            body_json = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                "error": "JSON inválido"
            }, status=400)

        nuevo_titulo = body_json.get('titulo')
        nuevo_contenido = body_json.get('contenido')

        if nuevo_titulo:
            foro.titulo = nuevo_titulo

        if nuevo_contenido:
            foro.contenido = nuevo_contenido

        foro.save()

        return JsonResponse({
            "message": "Foro actualizado",
            "foro": {
                "id": foro.id,
                "titulo": foro.titulo,
                "contenido": foro.contenido
            }
        }, status=200)

    # =========================
    # DELETE
    # =========================
    elif request.method == 'DELETE':

        foro.delete()

        return JsonResponse({
            "message": "Foro eliminado"
        }, status=200)

    return JsonResponse({
        "error": "HTTP method unsupported"
    }, status=405)