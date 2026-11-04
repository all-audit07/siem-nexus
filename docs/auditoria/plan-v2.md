# Plan v2.0: orientación a auditoría de seguridad

Objetivo: pasar de "detectar ataques" a "evaluar controles con evidencia verificable".

1. Modo auditoría del informe: hallazgos con condición, criterio, causa, efecto y recomendación, mapeados a ISO/IEC 27001:2022, CIS Controls v8 y NIST CSF 2.0.
2. Evaluación de cobertura de logging: qué controles no pueden auditarse con los registros disponibles.
3. Bóveda de evidencias en SQL Server con cadena de custodia (hash, quién, cuándo).
4. Registro de auditoría encadenado por hash y segregación de funciones (rol auditor de solo lectura).
5. Seguimiento de hallazgos: responsable, fecha comprometida, estado y evidencia de cierre.
