# Actualizar el backend de PhishARG en AWS

Para publicar cambios del backend hay que construir una imagen Docker, subirla a Amazon ECR y actualizar el servicio de ECS para ejecutar esa imagen. Un push a Git no actualiza AWS: este proyecto todavía usa despliegue manual.

## Recursos existentes

| Recurso | Valor |
|---|---|
| Rama del backend inicial | `aws-fargate-deployment` |
| Cuenta y región | `668281913895`, `us-east-1` |
| Repositorio ECR | `phisharg-api` |
| Cluster ECS | `phisharg-cluster` |
| Servicio ECS | `phisharg-service` |
| Familia y contenedor | `phisharg-api` |
| API | `https://api.phisharg.com` |
| Logs de CloudWatch | `/ecs/phisharg-api` |

Usar la revisión que utiliza actualmente el servicio como base de la siguiente. El 21/10/2026 se verificó `phisharg-api:4`, con cero tasks deseadas y cero en ejecución. Estos valores pueden cambiar después.

## 1. Preparar el código y Docker

Abrir Docker Desktop y esperar que el motor esté listo. En la terminal, desde el repositorio `flujo_v2`:

```bash
git switch aws-fargate-deployment
git pull --ff-only
git status --short
git log -1 --oneline
df -h .
docker info
docker buildx version
```

Si `git status --short` muestra archivos, revisarlos antes de continuar. Docker construye desde los archivos de la carpeta, incluidos los cambios sin commit. Para identificar la imagen con su commit, construir con el árbol limpio. Si `git pull` falla, resolver el motivo antes de publicar.

Tener varios GB libres, idealmente 10 a 15 GB para este build. Una falta de espacio anterior dejó el almacenamiento de Docker en modo de solo lectura; después de liberar espacio fue necesario reiniciar Docker Desktop. No ejecutar limpiezas masivas de imágenes o volúmenes sin revisar qué contienen.

La imagen usa Linux `amd64`, compatible con la task Fargate configurada. El `Dockerfile` copia la aplicación, sus dependencias y `model/phisharg_xgboost.pkl`. El `.dockerignore` excluye `.env`, `.env.*` y `model/*.gguf`, entre otros archivos. Si se cambia la ubicación del GGUF, revisar también esa exclusión.

## 2. Autenticar AWS y definir la etiqueta

```bash
export REGION=us-east-1
export ACCOUNT_ID=668281913895
export IMAGE_TAG="git-$(git rev-parse --short=12 HEAD)"
export IMAGE_URI="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/phisharg-api:$IMAGE_TAG"

aws sts get-caller-identity
```

El campo `Account` debe ser `668281913895`. Si la sesión venció, ejecutar `aws login`, completar el acceso y repetir la comprobación. Si se trabaja con un perfil, usar el mismo perfil para todos los comandos AWS.

```bash
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin \
    "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"
```

El resultado esperado es `Login Succeeded`. El comando envía la contraseña temporal directamente a Docker; no copiar ni publicar esa contraseña.

La etiqueta basada en el commit permite identificar la versión. Si ya existe en ECR, comprobar qué imagen representa antes de reutilizarla. Una reconstrucción del mismo commit puede generar bytes diferentes por cambios en dependencias o imágenes base; el digest es la identidad exacta de la imagen.

## 3. Construir la imagen y subirla a ECR

```bash
docker buildx build \
  --platform linux/amd64 \
  --tag "$IMAGE_URI" \
  --load \
  .
```

`--load` deja la imagen construida en Docker local. Comprobar su plataforma:

```bash
docker image inspect "$IMAGE_URI" \
  --format '{{.Os}}/{{.Architecture}}'
```

Debe mostrar `linux/amd64`. Después subirla:

```bash
docker push "$IMAGE_URI"
```

Esperar que termine sin errores. Publicar la imagen no modifica el servicio ECS ni enciende tasks.

## 4. Verificar la imagen publicada

```bash
aws ecr describe-images \
  --region "$REGION" \
  --registry-id "$ACCOUNT_ID" \
  --repository-name phisharg-api \
  --image-ids imageTag="$IMAGE_TAG" \
  --query 'imageDetails[0].{tags:imageTags,digest:imageDigest,publicada:imagePushedAt}' \
  --output json

echo "$IMAGE_URI"
```

Guardar la URI y el digest devueltos. Si la consulta no encuentra la imagen, no continuar con ECS hasta confirmar el push, la región y la cuenta.

## 5. Crear una nueva revisión de la task definition

En la consola AWS, seleccionar **N. Virginia / us-east-1**:

1. Entrar en **ECS → Clusters → phisharg-cluster → Services → phisharg-service**.
2. Abrir la task definition que figura como usada por el servicio. Anotar su revisión para poder volver atrás.
3. Elegir **Create new revision**. Si se usa el editor JSON, conservar la configuración de esa revisión.
4. En el contenedor `phisharg-api`, cambiar **Image URI** por la URI obtenida en el paso anterior.
5. Mantener CPU, RAM, roles, puertos, health checks, variables, logs y referencias a secretos. Crear la revisión y anotar su número.

La referencia de `API_KEY`, dentro de `secrets`, debe conservar el selector del campo JSON:

```json
{
  "name": "API_KEY",
  "valueFrom": "arn:aws:secretsmanager:us-east-1:668281913895:secret:phisharg/api-key-wyFU3E:API_KEY::"
}
```

El sufijo `:API_KEY::` extrae la clave del JSON guardado en Secrets Manager. Sin él, ECS inyecta el JSON completo y la autenticación falla con `401`. Nunca pegar el valor secreto como variable de texto plano. Si se recreó el secreto, usar su ARN vigente con ese selector.

Partir de la revisión operativa evita perder esta corrección al copiar una plantilla local antigua. Una revisión recién creada todavía no cambia las tasks del servicio.

## 6. Actualizar el servicio ECS

1. Volver a **phisharg-service → Update service**.
2. Seleccionar explícitamente el número de la nueva revisión de `phisharg-api`.
3. Para encender y probar la API, elegir **Desired tasks = 1**.
4. Conservar la red, `phisharg-task-sg`, la IP pública y la asociación al ALB y al target group existentes.
5. Confirmar la actualización y seguir **Deployments**, **Events** y **Logs**.

Cambiar la revisión inicia un deployment. No hace falta marcar además **Force new deployment**. Si se mantiene el servicio en cero, se puede actualizar su configuración, pero la API seguirá apagada y no se podrá probar hasta subir a uno.

Cada nueva task descarga y valida el GGUF desde S3 y lo carga antes de estar lista. Si el GGUF sigue siendo el mismo, conservar bucket, key, version ID y SHA-256: no hay que subirlo de nuevo. Si cambia el GGUF, subir la nueva versión y actualizar esos valores juntos antes de desplegar.

## 7. Verificar la actualización y volver atrás si falla

Esperar **Deployment status: Success**, una task en ejecución y el target saludable. Ejecutar:

```bash
curl -i https://api.phisharg.com/api/v1/health/ready
```

Debe responder `200`. Después analizar un correo de prueba desde Outlook y confirmar el veredicto visible y el `POST /api/v1/analyze` exitoso. Readiness por sí solo no valida el análisis completo. El dominio y `API_BASE_URL` no cambian al actualizar la imagen del backend.

Si falla, revisar **ECS → servicio → Events/Logs** y CloudWatch `/ecs/phisharg-api`. Distinguir un fallo de arranque, permisos de S3, checksum, autenticación o timeout. No dar por desplegada una imagen solo porque existe en ECR.

Para volver atrás, actualizar el servicio a la revisión anterior anotada en el paso 5. Conservar esa revisión y su imagen ECR hasta validar la nueva versión. El rollback también reemplaza tasks y debe verificarse con readiness y Outlook.

## 8. Apagar la demo

Al terminar, actualizar `phisharg-service` con **Desired tasks = 0** y esperar cero tasks en ejecución. La API quedará indisponible. Esto detiene las tasks Fargate; el ALB sigue creado y puede seguir generando cargos, al igual que almacenamiento y otros recursos. El ALB no se pausa al reducir ECS a cero.

## Referencias

- [Publicar una imagen en ECR](https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-push-ecr-image.html).
- [Exportar un build con `--load`](https://docs.docker.com/build/exporters/).
- [Actualizar una task definition y su servicio](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-task-definition-console-v2.html).
- [Extraer campos JSON de Secrets Manager en ECS](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html).
- [Preparación inicial del despliegue](AWS_ECS_DEPLOYMENT.md).