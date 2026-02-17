-- Script de prueba para verificar stored procedures de Exercise
USE bduna;

-- Verificar si existe la columna videoUrl
DESCRIBE tbExercise;

-- Contar ejercicios
SELECT COUNT(*) as 'Total Ejercicios' FROM tbExercise WHERE isDeleted = 0;

-- Probar prGetAllExercise
CALL prGetAllExercise();

-- Probar prGetExercise con parámetros básicos
CALL prGetExercise(1, 10, 1, '', '', '', 'active', 'all', NULL, @total);
SELECT @total as 'Total Records';
