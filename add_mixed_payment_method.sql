-- Script para agregar el medio de pago "Mixto"
-- Este medio de pago permite combinar Sinpe Móvil y Efectivo en una misma transacción

USE dbForceGym;

-- Insertar el nuevo medio de pago "Mixto" con ID 3
INSERT INTO tbMeanOfPayment (idMeanOfPayment, name) 
VALUES (3, 'Mixto');

-- Verificar que se insertó correctamente
SELECT * FROM tbMeanOfPayment;
