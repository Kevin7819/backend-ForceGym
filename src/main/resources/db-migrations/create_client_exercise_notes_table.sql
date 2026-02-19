-- Script para crear la tabla de notas personales de ejercicios por cliente
-- Esta tabla permite que cada cliente tenga sus propias notas en cada ejercicio de su rutina
-- Por ejemplo: registrar el peso usado, observaciones personales, etc.

USE dbforcegym;

-- Crear tabla tbClientExerciseNote
CREATE TABLE IF NOT EXISTS tbClientExerciseNote (
    idClientExerciseNote BIGINT AUTO_INCREMENT PRIMARY KEY,
    idClient INT NOT NULL,
    idRoutineExercise INT NOT NULL,
    personalNote TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_client_exercise_note_client 
        FOREIGN KEY (idClient) 
        REFERENCES tbClient(idClient)
        ON DELETE CASCADE,
    CONSTRAINT fk_client_exercise_note_routine_exercise 
        FOREIGN KEY (idRoutineExercise) 
        REFERENCES tbRoutineExercise(idRoutineExercise)
        ON DELETE CASCADE,
    -- Asegurar que cada cliente solo pueda tener una nota por ejercicio de rutina
    UNIQUE KEY uk_client_routine_exercise (idClient, idRoutineExercise)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Crear índice para mejorar la búsqueda por cliente
CREATE INDEX idx_client_exercise_note_client ON tbClientExerciseNote(idClient);

-- Crear índice para mejorar la búsqueda por ejercicio de rutina
CREATE INDEX idx_client_exercise_note_routine_exercise ON tbClientExerciseNote(idRoutineExercise);
