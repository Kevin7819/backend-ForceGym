-- Agregar campo de contraseña a la tabla de clientes
-- Este campo almacenará la contraseña personalizada del cliente (encriptada)
-- Si es NULL, el sistema utiliza la contraseña provisional: [Inicial]#[Cédula]
-- Ejemplo: G#703050481

ALTER TABLE tbClient 
ADD COLUMN password VARCHAR(255) NULL 
COMMENT 'Contraseña personalizada del cliente (encriptada). Si es NULL, usa contraseña provisional';
