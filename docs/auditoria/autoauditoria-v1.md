# Autoauditoría de SIEM NEXUS v1.0

Revisión de seguridad del propio proyecto antes de publicarlo (04/11/2026). Criterio: ISO/IEC 27001:2022, Anexo A.

| ID | Condición | Criterio | Causa | Efecto | Recomendación | Estado |
|---|---|---|---|---|---|---|
| H-01 | Contraseñas y JWT secret en texto plano en `docker-compose.yml` | 5.17 Información de autenticación | Configuración inicial sin gestión de secretos | Exposición al publicar el repositorio | Mover a `.env` excluido de Git y rotar | Cerrado: movidos y rotados |
| H-02 | El backend usaba una contraseña por defecto si faltaba la variable de entorno | 8.28 Codificación segura | Valores de respaldo de desarrollo | Credencial válida embebida en el código | Eliminar valores por defecto de secretos | Cerrado |
| H-03 | Healthcheck de MySQL con contraseña embebida y resultado positivo aunque el acceso fuera denegado | 8.16 Actividades de seguimiento | `mysqladmin ping` no valida la autenticación | Control que aparentaba funcionar sin comprobar nada | Usar la variable de entorno y validar el resultado | Cerrado |
| H-04 | Contraseñas de las cuentas demo escritas en el código de la página de login | 5.17 y 8.28 | Función de autocompletado para demostración | Cualquier visitante las obtiene del JavaScript del cliente | Eliminar contraseñas del cliente y cambiarlas | Abierto en el sistema desplegado; corregido en el repositorio |
| H-05 | Hashes bcrypt y clave maestra de SQL Server en scripts de datos iniciales | 5.17 | Scripts de laboratorio reutilizados | Ataque de diccionario fuera de línea | Sustituir por marcadores | Cerrado en el repositorio; clave maestra pendiente de cambio |
| H-06 | Capturas del borrador del informe mostraban contraseñas y JWT secret | 5.17 | Evidencias tomadas sin revisión de datos sensibles | Exposición en documentos compartidos | Revisar evidencias antes de publicarlas y rotar lo expuesto | Cerrado: secretos rotados |
| H-07 | La rotación de contraseñas dejó MySQL inaccesible temporalmente | 8.32 Gestión de cambios | El secreto nuevo se aplicó antes de guardarlo | Pérdida de acceso; recuperada sin pérdida de datos | Respaldo previo y guardar el secreto antes de aplicarlo | Cerrado: procedimiento corregido |
