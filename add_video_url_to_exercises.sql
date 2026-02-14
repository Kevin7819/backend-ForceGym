-- Agregar columna videoUrl a la tabla tbExercise
-- El campo es opcional (puede ser NULL)

ALTER TABLE tbExercise ADD COLUMN videoUrl VARCHAR(500) NULL;

-- Comentario: Esta columna almacenará URLs de videos de YouTube, Vimeo, etc.
-- para mostrar tutoriales o demostraciones de los ejercicios
