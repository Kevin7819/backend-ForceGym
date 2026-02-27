-- Migración para cambiar el tipo de dato de repetitions de INT a VARCHAR
-- Esto permite almacenar valores como "*" para indicar "al fallo" además de números

USE dbforcegym;

-- Cambiar el tipo de dato de la columna repetitions en tbRoutineExercise
ALTER TABLE tbRoutineExercise 
MODIFY repetitions VARCHAR(10);

-- Nota: Los valores numéricos existentes se convertirán automáticamente a VARCHAR
