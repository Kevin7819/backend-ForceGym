-- =============================================
-- Script rápido para agregar columna BMI
-- Ejecutar este si solo necesitas que funcione rápido
-- =============================================

-- Desactivar safe update mode temporalmente
SET SQL_SAFE_UPDATES = 0;

-- Agregar columna BMI si no existe
ALTER TABLE tbMeasurement 
ADD COLUMN IF NOT EXISTS bmi FLOAT NULL AFTER height;

-- Verificar
SELECT 'Columna BMI agregada. Ahora ejecuta el script completo update_measurement_add_bmi.sql para actualizar los procedimientos almacenados.' AS Mensaje;

-- Opcional: Calcular BMI para registros existentes
UPDATE tbMeasurement
SET bmi = ROUND(weight / POWER(height / 100, 2), 2)
WHERE bmi IS NULL AND weight IS NOT NULL AND height IS NOT NULL AND height > 0;

SELECT CONCAT('Total de registros actualizados con BMI: ', ROW_COUNT()) AS Info;

-- Reactivar safe update mode
SET SQL_SAFE_UPDATES = 1;
