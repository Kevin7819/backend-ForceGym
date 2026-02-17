-- Agregar campo de día a los ejercicios de rutina
-- Esto permite organizar rutinas por días de entrenamiento

USE dbforcegym;

-- Agregar columna dayNumber a tbRoutineExercise
ALTER TABLE tbRoutineExercise 
ADD COLUMN dayNumber INT NOT NULL DEFAULT 1 COMMENT 'Día de entrenamiento (1, 2, 3, etc.)';

-- Actualizar ejercicios existentes para asignarlos al día 1 por defecto
UPDATE tbRoutineExercise 
SET dayNumber = 1 
WHERE dayNumber IS NULL OR dayNumber = 0;

-- Crear índice para mejorar consultas por día
CREATE INDEX idx_routine_day ON tbRoutineExercise(idRoutine, dayNumber);
