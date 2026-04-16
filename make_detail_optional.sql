-- Script para hacer el campo "detalle" opcional
-- Fecha: 2026-04-15

USE dbforcegym;

-- 1. Hacer que detail sea opcional en tbEconomicIncome
ALTER TABLE tbEconomicIncome 
MODIFY COLUMN detail varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL;

-- 2. Hacer que detail sea opcional en tbEconomicExpense
ALTER TABLE tbEconomicExpense 
MODIFY COLUMN detail varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL;

SELECT 'Script ejecutado exitosamente. El campo "detail" ahora es opcional en ingresos y gastos.' AS Resultado;
