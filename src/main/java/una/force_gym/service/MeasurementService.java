package una.force_gym.service;

import java.time.LocalDate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.ParameterMode;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.StoredProcedureQuery;
import una.force_gym.domain.Measurement;
import una.force_gym.repository.MeasurementRepository;

@Service
public class MeasurementService {
    
    @Autowired
    private MeasurementRepository measurementRepository;


    @PersistenceContext
    private EntityManager entityManager;

    public Map<String, Object> getMeasurements(
        int idClient,
        int page, 
        int size, int searchType,
        String searchTerm, 
        String orderBy, 
        String directionOrderBy, 
        String filterByStatus,
        LocalDate  filterByDateRangeStart,
        LocalDate  filterByDateRangeEnd
        
    ) {
            
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetMeasurement", Measurement.class);
        
        // Parámetros de entrada
        query.registerStoredProcedureParameter("p_idClient", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_page", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_limit", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchType", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchTerm", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_orderBy", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_directionOrderBy", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByStatus", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByDateRangeStart", LocalDate.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByDateRangeEnd", LocalDate.class, ParameterMode.IN);
        

        // Parámetro de salida
        query.registerStoredProcedureParameter("p_totalRecords", Integer.class, ParameterMode.OUT);

        // Setear valores
        query.setParameter("p_idClient", idClient);
        query.setParameter("p_page", page);
        query.setParameter("p_limit", size);
        query.setParameter("p_searchType", searchType);
        query.setParameter("p_searchTerm", searchTerm);
        query.setParameter("p_orderBy", orderBy);
        query.setParameter("p_directionOrderBy", directionOrderBy);
        query.setParameter("p_filterByStatus", filterByStatus);
        query.setParameter("p_filterByDateRangeStart", filterByDateRangeStart);
        query.setParameter("p_filterByDateRangeEnd", filterByDateRangeEnd);
                
        // Ejecutar procedimiento
        query.execute();

        // Obtener los resultados
        List<?> rawResults = query.getResultList();
        List<Measurement> measurements = rawResults.stream()
            .filter(Measurement.class::isInstance) 
            .map(Measurement.class::cast)         
            .collect(Collectors.toList());
        Integer totalRecords = (Integer) query.getOutputParameterValue("p_totalRecords");

        // Mapear respuesta
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("measurements", measurements);
        responseData.put("totalRecords", totalRecords);
        
        return responseData;
    }
    @Transactional
    public int addMeasurement(Long pIdClient, 
                                        Date pMeasurementDate, 
                                        Float pWeight, 
                                        Float pHeight,
                                        Float pBmi, 
                                        Float pMuscleMass, 
                                        Float pBodyFatPercentage, 
                                        Float pVisceralFatPercentage, 
                                        Float pChestSize,
                                        Float pBackSize,
                                        Float pHipSize, 
                                        Float pWaistSize,
                                        Float pLeftLegSize, 
                                        Float pRightLegSize, 
                                        Float pLeftCalfSize, 
                                        Float pRightCalfSize, 
                                        Float pLeftForeArmSize, 
                                        Float pRightForeArmSize, 
                                        Float pLeftArmSize, 
                                        Float pRightArmSize, 
                                        Long pLoggedIdUser) {
        return measurementRepository.addMeasurement(pIdClient, 
                                                    pMeasurementDate, 
                                                    pWeight,
                                                    pHeight,
                                                    pBmi,
                                                    pMuscleMass,
                                                    pBodyFatPercentage,
                                                    pVisceralFatPercentage,
                                                    pChestSize,
                                                    pBackSize,
                                                    pHipSize,
                                                    pWaistSize,
                                                    pLeftLegSize,
                                                    pRightLegSize,
                                                    pLeftCalfSize,
                                                    pRightCalfSize,
                                                    pLeftForeArmSize,
                                                    pRightForeArmSize,
                                                    pLeftArmSize,
                                                    pRightArmSize,
                                                    pLoggedIdUser);
    }

    @Transactional
    public int updateMeasurement(Long pIdMeasurement, 
                                            Long pIdClient, 
                                            Date pMeasurementDate, 
                                            Float pWeight, 
                                            Float pHeight,
                                            Float pBmi, 
                                            Float pMuscleMass, 
                                            Float pBodyFatPercentage, 
                                            Float pVisceralFatPercentage, 
                                            Float pChestSize,
                                            Float pBackSize,
                                            Float pHipSize,  
                                            Float pWaistSize,
                                            Float pLeftLegSize, 
                                            Float pRightLegSize, 
                                            Float pLeftCalfSize, 
                                            Float pRightCalfSize, 
                                            Float pLeftForeArmSize, 
                                            Float pRightForeArmSize, 
                                            Float pLeftArmSize, 
                                            Float pRightArmSize, 
                                            Long pIsDeleted,
                                            Long pLoggedIdUser) {
        return measurementRepository.updateMeasurement(pIdMeasurement, 
                                                        pIdClient,
                                                        pMeasurementDate, 
                                                        pWeight,
                                                        pHeight,
                                                        pBmi, 
                                                        pMuscleMass, 
                                                        pBodyFatPercentage, 
                                                        pVisceralFatPercentage,
                                                        pChestSize,
                                                        pBackSize,
                                                        pHipSize,
                                                        pWaistSize,
                                                        pLeftLegSize,
                                                        pRightLegSize,
                                                        pLeftCalfSize,
                                                        pRightCalfSize,
                                                        pLeftForeArmSize,
                                                        pRightForeArmSize,
                                                        pLeftArmSize,
                                                        pRightArmSize,
                                                        pIsDeleted,
                                                        pLoggedIdUser);
    }

    @Transactional
    public int deleteMeasurement(Long pIdMeasurement, Long pLoggedIdUser){
        return measurementRepository.deleteMeasurement(pIdMeasurement, pLoggedIdUser);
    }

    @Transactional
    public int importMeasurementsFromExcel(org.springframework.web.multipart.MultipartFile file, Long idClient) throws Exception {
        int importedCount = 0;
        
        System.out.println("Iniciando importación de medidas para cliente: " + idClient);
        System.out.println("Archivo: " + file.getOriginalFilename() + ", Tamaño: " + file.getSize() + " bytes");
        
        try (org.apache.poi.ss.usermodel.Workbook workbook = org.apache.poi.ss.usermodel.WorkbookFactory.create(file.getInputStream())) {
            org.apache.poi.ss.usermodel.Sheet sheet = workbook.getSheetAt(0);
            
            System.out.println("Total de filas en el Excel: " + sheet.getLastRowNum());
            
            // Buscar la estatura del cliente (está arriba en una celda fija)
            // Buscar en las primeras 15 filas por una celda que contenga "Estatura" o "Altura"
            Float clientHeight = 0f;
            for (int i = 0; i <= Math.min(15, sheet.getLastRowNum()); i++) {
                org.apache.poi.ss.usermodel.Row row = sheet.getRow(i);
                if (row != null) {
                    for (int col = 0; col <= 10; col++) {
                        org.apache.poi.ss.usermodel.Cell cell = row.getCell(col);
                        if (cell != null && cell.getCellType() == org.apache.poi.ss.usermodel.CellType.STRING) {
                            String cellValue = cell.getStringCellValue().trim().toLowerCase();
                            if (cellValue.contains("estatura") || cellValue.contains("altura")) {
                                // La estatura debe estar en una celda cercana (siguiente celda o siguiente columna)
                                // Intentar leer de la celda siguiente en la misma fila
                                for (int nextCol = col + 1; nextCol <= col + 3; nextCol++) {
                                    org.apache.poi.ss.usermodel.Cell valueCell = row.getCell(nextCol);
                                    if (valueCell != null) {
                                        Float heightValue = getCellFloatValue(valueCell);
                                        if (heightValue > 0f && heightValue < 3f) {
                                            // Estatura válida en metros (0.5 a 3.0)
                                            clientHeight = heightValue * 100f; // Convertir a cm
                                            System.out.println("Estatura del cliente encontrada: " + heightValue + " m = " + clientHeight + " cm");
                                            break;
                                        }
                                    }
                                }
                                if (clientHeight > 0f) break;
                            }
                        }
                    }
                    if (clientHeight > 0f) break;
                }
            }
            
            if (clientHeight == 0f) {
                System.out.println("⚠️ No se encontró la estatura del cliente en el Excel, se usará 0");
            }
            
            // Buscar la fila de headers (buscar la fila que contenga "Fecha" o "FECHA")
            int headerRowIndex = -1;
            for (int i = 0; i <= Math.min(20, sheet.getLastRowNum()); i++) {
                org.apache.poi.ss.usermodel.Row row = sheet.getRow(i);
                if (row != null && row.getCell(0) != null) {
                    String cellValue = row.getCell(0).toString().trim().toLowerCase();
                    if (cellValue.equals("fecha")) {
                        headerRowIndex = i;
                        System.out.println("Headers encontrados en fila " + (i + 1));
                        
                        // Mostrar los headers para verificar el orden
                        System.out.print("Headers encontrados: ");
                        for (int col = 0; col <= 13; col++) {
                            org.apache.poi.ss.usermodel.Cell headerCell = row.getCell(col);
                            if (headerCell != null) {
                                System.out.print("[" + col + "]" + headerCell.toString() + " | ");
                            }
                        }
                        System.out.println();
                        
                        break;
                    }
                }
            }
            
            if (headerRowIndex == -1) {
                throw new Exception("No se encontró la fila de encabezados con 'Fecha'");
            }
            
            // Procesar filas de datos (después de los headers)
            for (int i = headerRowIndex + 1; i <= sheet.getLastRowNum(); i++) {
                org.apache.poi.ss.usermodel.Row row = sheet.getRow(i);
                if (row == null) {
                    System.out.println("Fila " + (i + 1) + " está vacía, saltando...");
                    continue;
                }
                
                // Validar que la primera celda (fecha) no esté vacía
                if (row.getCell(0) == null || row.getCell(0).toString().trim().isEmpty()) {
                    System.out.println("Fila " + (i + 1) + " sin fecha, saltando...");
                    continue;
                }
                
                try {
                    System.out.println("Procesando fila " + (i + 1) + "...");
                    
                    // Estructura del Excel:
                    // A(0): Fecha, B(1): Peso, C(2): IMC, D(3): M.M, E(4): %G.Corp, F(5): %G.Visc,
                    // G(6): Pecho, H(7): Espalda, I(8): Cintura, J(9): Cadera,
                    // K(10): Pierna, L(11): Pantorrilla, M(12): Antebrazo, N(13): Brazo
                    
                    java.time.LocalDate measurementDate = getCellDateValue(row.getCell(0));
                    Float weight = getCellFloatValue(row.getCell(1));
                    Float bmi = getCellFloatValue(row.getCell(2));
                    Float muscleMass = getCellFloatValue(row.getCell(3));
                    
                    // Leer porcentajes con logging detallado
                    org.apache.poi.ss.usermodel.Cell bodyFatCell = row.getCell(4);
                    org.apache.poi.ss.usermodel.Cell visceralFatCell = row.getCell(5);
                    
                    System.out.println("  📊 Analizando % G.Corp (celda E" + (i + 1) + "):");
                    Float bodyFatPercentage = getCellFloatValue(bodyFatCell, true);
                    
                    System.out.println("  📊 Analizando %G.Visc (celda F" + (i + 1) + "):");
                    Float visceralFatPercentage = getCellFloatValue(visceralFatCell, true);
                    
                    Float chestSize = getCellFloatValue(row.getCell(6));
                    Float backSize = getCellFloatValue(row.getCell(7));
                    Float waistSize = getCellFloatValue(row.getCell(8));
                    Float hipSize = getCellFloatValue(row.getCell(9));
                    
                    // Leer medidas bilaterales (pueden estar como "57.5-58.5" o "58/58")
                    Float[] legSizes = getCellBilateralValues(row.getCell(10));
                    Float[] calfSizes = getCellBilateralValues(row.getCell(11));
                    Float[] foreArmSizes = getCellBilateralValues(row.getCell(12));
                    Float[] armSizes = getCellBilateralValues(row.getCell(13));
                    
                    System.out.println("Datos leídos: Fecha=" + measurementDate + ", Peso=" + weight + ", IMC=" + bmi + 
                                     ", MM=" + muscleMass + ", %GC=" + bodyFatPercentage + ", %GV=" + visceralFatPercentage + 
                                     ", Pecho=" + chestSize + ", Espalda=" + backSize + ", Cintura=" + waistSize + 
                                     ", Cadera=" + hipSize + 
                                     ", Pierna Izq=" + legSizes[0] + ", Pierna Der=" + legSizes[1] + 
                                     ", Pantorrilla Izq=" + calfSizes[0] + ", Pantorrilla Der=" + calfSizes[1] + 
                                     ", Antebrazo Izq=" + foreArmSizes[0] + ", Antebrazo Der=" + foreArmSizes[1] + 
                                     ", Brazo Izq=" + armSizes[0] + ", Brazo Der=" + armSizes[1]);
                    
                    System.out.println("💾 COMPARACIÓN - Lo que muestra Excel vs Lo que se guardará:");
                    System.out.println("   Excel % G.Corp: " + (bodyFatCell != null ? bodyFatCell.toString() : "null") + " → DB: " + bodyFatPercentage);
                    System.out.println("   Excel %G.Visc: " + (visceralFatCell != null ? visceralFatCell.toString() : "null") + " → DB: " + visceralFatPercentage);
                    
                    // Validar que haya datos mínimos
                    if (measurementDate == null || weight == null || weight == 0f) {
                        System.out.println("Fila " + (i + 1) + " no tiene datos mínimos (fecha o peso), saltando...");
                        continue;
                    }
                    
                    // Convertir LocalDate a java.util.Date para el stored procedure
                    java.util.Date measurementDateUtil = java.sql.Date.valueOf(measurementDate);
                    
                    System.out.println("Valores a insertar en DB:");
                    System.out.println("  idClient: " + idClient);
                    System.out.println("  fecha: " + measurementDateUtil);
                    System.out.println("  peso: " + (weight != null ? weight : 0f));
                    System.out.println("  altura: " + clientHeight + " cm");
                    System.out.println("  bmi: " + (bmi != null ? bmi : 0f));
                    System.out.println("  muscleMass: " + (muscleMass != null ? muscleMass : 0f));
                    System.out.println("  bodyFatPercentage: " + (bodyFatPercentage != null ? bodyFatPercentage : 0f));
                    System.out.println("  visceralFatPercentage: " + (visceralFatPercentage != null ? visceralFatPercentage : 0f));
                    System.out.println("  chestSize: " + (chestSize != null ? chestSize : 0f));
                    System.out.println("  backSize: " + (backSize != null ? backSize : 0f));
                    System.out.println("  hipSize: " + (hipSize != null ? hipSize : 0f));
                    System.out.println("  waistSize: " + (waistSize != null ? waistSize : 0f));
                    System.out.println("  leftLegSize: " + legSizes[0]);
                    System.out.println("  rightLegSize: " + legSizes[1]);
                    System.out.println("  leftCalfSize: " + calfSizes[0]);
                    System.out.println("  rightCalfSize: " + calfSizes[1]);
                    System.out.println("  leftForeArmSize: " + foreArmSizes[0]);
                    System.out.println("  rightForeArmSize: " + foreArmSizes[1]);
                    System.out.println("  leftArmSize: " + armSizes[0]);
                    System.out.println("  rightArmSize: " + armSizes[1]);
                    
                    // Insertar la medida con valores diferenciados para izquierda y derecha
                    // Usar la estatura del cliente encontrada en el Excel
                    int result = addMeasurement(
                        idClient,
                        measurementDateUtil,
                        weight != null ? weight : 0f,
                        clientHeight, // altura del cliente leída del Excel
                        bmi != null ? bmi : 0f,
                        muscleMass != null ? muscleMass : 0f,
                        bodyFatPercentage != null ? bodyFatPercentage : 0f,
                        visceralFatPercentage != null ? visceralFatPercentage : 0f,
                        chestSize != null ? chestSize : 0f,
                        backSize != null ? backSize : 0f,
                        hipSize != null ? hipSize : 0f,
                        waistSize != null ? waistSize : 0f,
                        legSizes[0],      // pierna izq
                        legSizes[1],      // pierna der
                        calfSizes[0],     // pantorrilla izq
                        calfSizes[1],     // pantorrilla der
                        foreArmSizes[0],  // antebrazo izq
                        foreArmSizes[1],  // antebrazo der
                        armSizes[0],      // brazo izq
                        armSizes[1],      // brazo der
                        1L // ID de usuario por defecto para importaciones
                    );
                    
                    System.out.println("Llamando a stored procedure con idClient=" + idClient + ", resultado: " + result);
                    
                    if (result == 1) {
                        importedCount++;
                        System.out.println("Fila " + (i + 1) + " importada exitosamente");
                    } else if (result == -1) {
                        System.err.println("Error al importar fila " + (i + 1) + ": Cliente no existe");
                    } else {
                        System.err.println("Error al importar fila " + (i + 1) + ": Error en transacción SQL (result=0)");
                    }
                } catch (Exception e) {
                    // Continuar con la siguiente fila si hay error
                    System.err.println("Error procesando fila " + (i + 1) + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            System.err.println("Error al leer el archivo Excel: " + e.getMessage());
            e.printStackTrace();
            throw new Exception("Error al procesar el archivo Excel: " + e.getMessage(), e);
        }
        
        System.out.println("Importación completada. Total de medidas importadas: " + importedCount);
        return importedCount;
    }
    
    private java.time.LocalDate getCellDateValue(org.apache.poi.ss.usermodel.Cell cell) {
        if (cell == null) return java.time.LocalDate.now();
        
        try {
            if (cell.getCellType() == org.apache.poi.ss.usermodel.CellType.NUMERIC) {
                if (org.apache.poi.ss.usermodel.DateUtil.isCellDateFormatted(cell)) {
                    return cell.getLocalDateTimeCellValue().toLocalDate();
                }
            } else if (cell.getCellType() == org.apache.poi.ss.usermodel.CellType.STRING) {
                // Intentar parsear string como fecha (formato yyyy-MM-dd o dd/MM/yyyy o d/M/yy)
                String dateStr = cell.getStringCellValue().trim();
                if (dateStr.contains("/")) {
                    String[] parts = dateStr.split("/");
                    int day = Integer.parseInt(parts[0]);
                    int month = Integer.parseInt(parts[1]);
                    int year = Integer.parseInt(parts[2]);
                    
                    // Convertir año de 2 dígitos a 4 dígitos
                    if (year < 100) {
                        year += (year < 50) ? 2000 : 1900;
                    }
                    
                    return java.time.LocalDate.of(year, month, day);
                } else if (dateStr.contains("-")) {
                    return java.time.LocalDate.parse(dateStr);
                }
            }
        } catch (Exception e) {
            System.err.println("Error al parsear fecha: " + cell.toString() + " - " + e.getMessage());
            // Si falla, retornar fecha actual
        }
        
        return java.time.LocalDate.now();
    }
    
    private Float getCellFloatValue(org.apache.poi.ss.usermodel.Cell cell) {
        return getCellFloatValue(cell, false);
    }
    
    private Float getCellFloatValue(org.apache.poi.ss.usermodel.Cell cell, boolean debugMode) {
        if (cell == null) return 0f;
        
        try {
            org.apache.poi.ss.usermodel.CellType cellType = cell.getCellType();
            
            // Si es una fórmula, evaluar primero
            if (cellType == org.apache.poi.ss.usermodel.CellType.FORMULA) {
                cellType = cell.getCachedFormulaResultType();
            }
            
            if (cellType == org.apache.poi.ss.usermodel.CellType.NUMERIC) {
                String formatString = cell.getCellStyle().getDataFormatString();
                
                // Si es porcentaje, usar el DataFormatter para obtener el valor COMO LO MUESTRA Excel
                if (formatString != null && formatString.contains("%")) {
                    try {
                        org.apache.poi.ss.usermodel.DataFormatter formatter = new org.apache.poi.ss.usermodel.DataFormatter();
                        String formattedValue = formatter.formatCellValue(cell);
                        
                        if (debugMode) {
                            System.out.println("    [DEBUG] Tipo: NUMERIC con formato %");
                            System.out.println("    [DEBUG] Valor RAW interno: " + cell.getNumericCellValue());
                            System.out.println("    [DEBUG] Formato: " + formatString);
                            System.out.println("    [DEBUG] Como lo MUESTRA Excel: '" + formattedValue + "'");
                        }
                        
                        // Parsear el valor formateado (ej: "10%" → 10)
                        String cleanValue = formattedValue.replace("%", "").replace(",", ".").trim();
                        float result = Float.parseFloat(cleanValue);
                        
                        if (debugMode) {
                            System.out.println("    [DEBUG] ✅ Valor a guardar: " + result);
                        }
                        
                        return result;
                    } catch (Exception e) {
                        System.err.println("    [ERROR] No se pudo parsear porcentaje formateado, usando valor RAW");
                        if (debugMode) {
                            e.printStackTrace();
                        }
                        // Fallback: usar el valor numérico * 100
                        return (float) (cell.getNumericCellValue() * 100);
                    }
                }
                
                // No es porcentaje, retornar el valor numérico directo
                double value = cell.getNumericCellValue();
                if (debugMode) {
                    System.out.println("    [DEBUG] Tipo: NUMERIC (no %)");
                    System.out.println("    [DEBUG] Valor: " + value);
                }
                return (float) value;
            } else if (cellType == org.apache.poi.ss.usermodel.CellType.STRING) {
                String value = cell.getStringCellValue().trim();
                
                if (value.isEmpty()) return 0f;
                
                if (debugMode) {
                    System.out.println("    [DEBUG] Tipo: STRING, valor: '" + value + "'");
                }
                
                // Reemplazar coma por punto
                value = value.replace(",", ".");
                
                // Si tiene %, quitar el símbolo y tomar el número
                if (value.endsWith("%")) {
                    value = value.substring(0, value.length() - 1).trim();
                    float result = Float.parseFloat(value);
                    if (debugMode) {
                        System.out.println("    [DEBUG] ✅ String con %, guardará: " + result);
                    }
                    return result;
                }
                
                // Número simple
                float result = Float.parseFloat(value);
                if (debugMode) {
                    System.out.println("    [DEBUG] Número simple, guardará: " + result);
                }
                return result;
            }
        } catch (Exception e) {
            System.err.println("❌ Error al parsear celda: " + cell.toString() + " - " + e.getMessage());
            e.printStackTrace();
        }
        
        return 0f;
    }
    
    // Método para leer valores bilaterales (izq/der) separados por - o /
    private Float[] getCellBilateralValues(org.apache.poi.ss.usermodel.Cell cell) {
        Float[] result = new Float[2]; // [izquierdo, derecho]
        
        if (cell == null) {
            result[0] = 0f;
            result[1] = 0f;
            return result;
        }
        
        try {
            org.apache.poi.ss.usermodel.CellType cellType = cell.getCellType();
            
            if (cellType == org.apache.poi.ss.usermodel.CellType.FORMULA) {
                cellType = cell.getCachedFormulaResultType();
            }
            
            if (cellType == org.apache.poi.ss.usermodel.CellType.NUMERIC) {
                // Si es número simple, usar el mismo valor para ambos lados
                float value = (float) cell.getNumericCellValue();
                result[0] = value;
                result[1] = value;
                return result;
            } else if (cellType == org.apache.poi.ss.usermodel.CellType.STRING) {
                String value = cell.getStringCellValue().trim();
                
                if (value.isEmpty()) {
                    result[0] = 0f;
                    result[1] = 0f;
                    return result;
                }
                
                // Reemplazar coma por punto
                value = value.replace(",", ".");
                
                // Detectar si es un rango con guión o barra
                String separator = null;
                if (value.contains("-") && !value.startsWith("-")) {
                    separator = "-";
                } else if (value.contains("/")) {
                    separator = "/";
                }
                
                if (separator != null) {
                    String[] parts = value.split(separator);
                    if (parts.length == 2) {
                        String secondPart = parts[1].trim();
                        if (!secondPart.isEmpty()) {
                            // Tiene dos valores: primero=izq, segundo=der
                            result[0] = Float.parseFloat(parts[0].trim());
                            result[1] = Float.parseFloat(secondPart);
                            return result;
                        }
                    }
                    // Si tiene "/" o "-" pero sin segundo valor, usar el primero para ambos
                    float singleValue = Float.parseFloat(parts[0].trim());
                    result[0] = singleValue;
                    result[1] = singleValue;
                    return result;
                }
                
                // Valor simple, usar para ambos lados
                float singleValue = Float.parseFloat(value);
                result[0] = singleValue;
                result[1] = singleValue;
                return result;
            }
        } catch (Exception e) {
            System.err.println("Error al parsear valores bilaterales de celda: " + cell.toString() + " - " + e.getMessage());
        }
        
        result[0] = 0f;
        result[1] = 0f;
        return result;
    }
}

