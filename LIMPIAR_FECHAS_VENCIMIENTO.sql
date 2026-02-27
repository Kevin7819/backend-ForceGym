-- ================================================================
-- SCRIPT PARA LIMPIAR FECHAS DE VENCIMIENTO DE CLIENTES
-- ================================================================
-- Este script establece a NULL todas las fechas de vencimiento de membresía
-- que fueron asignadas incorrectamente igual a la fecha de registro
-- ================================================================

USE dbforcegym;

-- ================================================================
-- DESACTIVAR MODO SEGURO TEMPORALMENTE
-- ================================================================
SET SQL_SAFE_UPDATES = 0;

-- ================================================================
-- PASO 1: VERIFICAR DATOS ANTES DE ACTUALIZAR
-- ================================================================
SELECT 
    'ANTES DE LIMPIAR' AS Estado,
    COUNT(*) AS TotalClientes,
    SUM(CASE WHEN expirationMembershipDate IS NOT NULL THEN 1 ELSE 0 END) AS ClientesConFechaVencimiento,
    SUM(CASE WHEN expirationMembershipDate IS NULL THEN 1 ELSE 0 END) AS ClientesSinFechaVencimiento,
    SUM(CASE WHEN expirationMembershipDate = registrationDate THEN 1 ELSE 0 END) AS FechasIgualesARegistro
FROM tbClient
WHERE isDeleted = 0;

-- ================================================================
-- PASO 2: ACTUALIZAR - ESTABLECER TODAS LAS FECHAS A NULL
-- ================================================================
UPDATE tbClient
SET expirationMembershipDate = NULL
WHERE isDeleted = 0;

-- ================================================================
-- PASO 3: VERIFICAR DATOS DESPUÉS DE ACTUALIZAR
-- ================================================================
SELECT 
    'DESPUÉS DE LIMPIAR' AS Estado,
    COUNT(*) AS TotalClientes,
    SUM(CASE WHEN expirationMembershipDate IS NOT NULL THEN 1 ELSE 0 END) AS ClientesConFechaVencimiento,
    SUM(CASE WHEN expirationMembershipDate IS NULL THEN 1 ELSE 0 END) AS ClientesSinFechaVencimiento
FROM tbClient
WHERE isDeleted = 0;

-- ================================================================
-- CONFIRMACIÓN
-- ================================================================
SELECT 
    '✅ LIMPIEZA COMPLETADA' AS Resultado,
    'Todas las fechas de vencimiento han sido establecidas a NULL' AS Mensaje,
    'Los clientes ahora necesitan un pago de membresía para tener fecha de vencimiento' AS Nota;

-- ================================================================
-- REACTIVAR MODO SEGURO
-- ================================================================
SET SQL_SAFE_UPDATES = 1;
