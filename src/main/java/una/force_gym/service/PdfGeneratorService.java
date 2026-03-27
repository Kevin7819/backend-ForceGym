package una.force_gym.service;

import java.io.ByteArrayOutputStream;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.Period;
import java.util.List;

import org.springframework.stereotype.Service;

import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.geom.PageSize;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.AreaBreak;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.AreaBreakType;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import com.itextpdf.layout.properties.VerticalAlignment;

import una.force_gym.domain.Client;
import una.force_gym.domain.Measurement;
import una.force_gym.domain.RoutineAssignment;
import una.force_gym.domain.RoutineExercise;

@Service
public class PdfGeneratorService {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("dd/MM/yyyy");
    private static final DeviceRgb HEADER_COLOR = new DeviceRgb(41, 128, 185); // Azul
    private static final DeviceRgb CELL_COLOR = new DeviceRgb(236, 240, 241); // Gris claro
    
    // Colores para cada día de entrenamiento
    private static final DeviceRgb[] DAY_COLORS = {
        new DeviceRgb(207, 173, 4),   // Día 1 - Amarillo
        new DeviceRgb(0, 123, 255),   // Día 2 - Azul
        new DeviceRgb(40, 167, 69),   // Día 3 - Verde
        new DeviceRgb(255, 159, 64),  // Día 4 - Naranja
        new DeviceRgb(111, 66, 193),  // Día 5 - Púrpura
        new DeviceRgb(220, 53, 69),   // Día 6 - Rojo
        new DeviceRgb(23, 162, 184)   // Día 7 - Cian
    };

    /**
     * Genera un PDF con las rutinas asignadas a un cliente
     */
    public byte[] generateRoutinesPdf(Client client, List<RoutineAssignment> routines) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfWriter writer = null;
        PdfDocument pdf = null;
        Document document = null;
        
        try {
            writer = new PdfWriter(baos);
            pdf = new PdfDocument(writer);
            document = new Document(pdf);

        // Fecha y hora actuales
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
        SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
        String currentDate = dateFormat.format(new java.util.Date());
        String currentTime = timeFormat.format(new java.util.Date());

        // Header con información del reporte
        Paragraph header = new Paragraph("REPORTE DE RUTINAS ASIGNADAS")
                .setFontSize(18)
                .setBold()
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(5);
        document.add(header);

        // Línea separadora
        com.itextpdf.layout.element.LineSeparator lineSeparator1 = 
            new com.itextpdf.layout.element.LineSeparator(
                new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(0.5f));
        lineSeparator1.setMarginTop(5);
        lineSeparator1.setMarginBottom(10);
        document.add(lineSeparator1);

        // Información del cliente y reporte
        Paragraph reportInfo = new Paragraph(
                "Cliente: " + client.getPerson().getName() + " " + 
                client.getPerson().getFirstLastName() + " " + 
                client.getPerson().getSecondLastName() + "\n" +
                "Cédula: " + client.getPerson().getIdentificationNumber() + "\n" +
                "Fecha del reporte: " + currentDate + "\n" +
                "Hora del reporte: " + currentTime
        ).setFontSize(10).setMarginBottom(15);
        document.add(reportInfo);

        // Línea separadora
        com.itextpdf.layout.element.LineSeparator lineSeparator2 = 
            new com.itextpdf.layout.element.LineSeparator(
                new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(0.5f));
        lineSeparator2.setMarginBottom(15);
        document.add(lineSeparator2);

        // Iterar sobre las rutinas
        for (RoutineAssignment assignment : routines) {
            // Nombre de la rutina
            Paragraph routineName = new Paragraph(assignment.getRoutine().getName())
                    .setFontSize(16)
                    .setBold()
                    .setMarginTop(10)
                    .setMarginBottom(5);
            document.add(routineName);

            // Información de la rutina
            Paragraph routineInfo = new Paragraph(
                    "Fecha de asignación: " + DATE_FORMAT.format(assignment.getAssignmentDate()) + " | " +
                    "Dificultad: " + (assignment.getRoutine().getDifficultyRoutine() != null ? 
                        assignment.getRoutine().getDifficultyRoutine().getName() : "N/A")
            ).setFontSize(9).setMarginBottom(10);
            document.add(routineInfo);

            // Tabla de ejercicios
            if (assignment.getRoutine().getExercises() != null && 
                !assignment.getRoutine().getExercises().isEmpty()) {
                
                // Agrupar ejercicios por día
                java.util.Map<Integer, java.util.List<RoutineExercise>> exercisesByDay = new java.util.TreeMap<>();
                for (RoutineExercise re : assignment.getRoutine().getExercises()) {
                    Integer day = re.getDayNumber() != null ? re.getDayNumber() : 1;
                    exercisesByDay.computeIfAbsent(day, k -> new java.util.ArrayList<>()).add(re);
                }

                // Crear sección para cada día
                for (java.util.Map.Entry<Integer, java.util.List<RoutineExercise>> dayEntry : exercisesByDay.entrySet()) {
                    Integer dayNumber = dayEntry.getKey();
                    DeviceRgb dayColor = DAY_COLORS[(dayNumber - 1) % DAY_COLORS.length];
                    
                    // Título del día (más grande y destacado)
                    Paragraph dayTitle = new Paragraph("DÍA " + dayNumber)
                            .setFontSize(16)
                            .setBold()
                            .setFontColor(dayColor)
                            .setMarginTop(12)
                            .setMarginBottom(2);
                    document.add(dayTitle);
                    
                    // Línea divisoria del día
                    com.itextpdf.layout.element.LineSeparator lineSeparator = 
                        new com.itextpdf.layout.element.LineSeparator(
                            new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(2f));
                    lineSeparator.setStrokeColor(dayColor);
                    lineSeparator.setMarginBottom(8);
                    document.add(lineSeparator);

                    // Agrupar ejercicios del día por categoría
                    java.util.Map<String, java.util.List<RoutineExercise>> exercisesByCategory = new java.util.HashMap<>();
                    for (RoutineExercise re : dayEntry.getValue()) {
                        String category = (re.getExercise() != null && 
                                         re.getExercise().getExerciseCategory() != null && 
                                         re.getExercise().getExerciseCategory().getName() != null) 
                                ? re.getExercise().getExerciseCategory().getName() 
                                : "Otros";
                        exercisesByCategory.computeIfAbsent(category, k -> new java.util.ArrayList<>()).add(re);
                    }
                    
                    // Ordenar ejercicios dentro de cada categoría por categoryOrder y luego por id
                    for (java.util.List<RoutineExercise> exercises : exercisesByCategory.values()) {
                        exercises.sort((a, b) -> {
                            Integer orderA = a.getCategoryOrder() != null ? a.getCategoryOrder() : Integer.MAX_VALUE;
                            Integer orderB = b.getCategoryOrder() != null ? b.getCategoryOrder() : Integer.MAX_VALUE;
                            
                            if (!orderA.equals(orderB)) {
                                return orderA.compareTo(orderB);
                            }
                            
                            Long idA = a.getIdRoutineExercise() != null ? a.getIdRoutineExercise() : 0L;
                            Long idB = b.getIdRoutineExercise() != null ? b.getIdRoutineExercise() : 0L;
                            return idA.compareTo(idB);
                        });
                    }

                    // Ordenar categorías por el mínimo categoryOrder de sus ejercicios
                    java.util.List<java.util.Map.Entry<String, java.util.List<RoutineExercise>>> sortedCategories = 
                        new java.util.ArrayList<>(exercisesByCategory.entrySet());
                    sortedCategories.sort((a, b) -> {
                        Integer minOrderA = a.getValue().stream()
                            .map(RoutineExercise::getCategoryOrder)
                            .min(Integer::compareTo)
                            .orElse(Integer.MAX_VALUE);
                        Integer minOrderB = b.getValue().stream()
                            .map(RoutineExercise::getCategoryOrder)
                            .min(Integer::compareTo)
                            .orElse(Integer.MAX_VALUE);
                        return minOrderA.compareTo(minOrderB);
                    });

                    // Crear tabla para cada categoría (usando el color del día)
                    for (java.util.Map.Entry<String, java.util.List<RoutineExercise>> categoryEntry : sortedCategories) {
                        // Título de la categoría
                        Paragraph categoryTitle = new Paragraph("Categoría: " + categoryEntry.getKey())
                                .setFontSize(12)
                                .setBold()
                                .setFontColor(dayColor)
                                .setMarginTop(8)
                                .setMarginBottom(4)
                                .setMarginLeft(10);
                        document.add(categoryTitle);

                        Table table = new Table(UnitValue.createPercentArray(new float[]{3, 1, 1, 2}))
                                .setWidth(UnitValue.createPercentValue(100))
                                .setMarginLeft(15);

                        // Encabezados con el color del día
                        Cell headerCell1 = new Cell()
                                .add(new Paragraph("Ejercicio").setBold().setFontColor(ColorConstants.WHITE))
                                .setBackgroundColor(dayColor)
                                .setTextAlignment(TextAlignment.CENTER)
                                .setPadding(5);
                        Cell headerCell2 = new Cell()
                                .add(new Paragraph("Series").setBold().setFontColor(ColorConstants.WHITE))
                                .setBackgroundColor(dayColor)
                                .setTextAlignment(TextAlignment.CENTER)
                                .setPadding(5);
                        Cell headerCell3 = new Cell()
                                .add(new Paragraph("Repeticiones").setBold().setFontColor(ColorConstants.WHITE))
                                .setBackgroundColor(dayColor)
                                .setTextAlignment(TextAlignment.CENTER)
                                .setPadding(5);
                        Cell headerCell4 = new Cell()
                                .add(new Paragraph("Notas").setBold().setFontColor(ColorConstants.WHITE))
                                .setBackgroundColor(dayColor)
                                .setTextAlignment(TextAlignment.CENTER)
                                .setPadding(5);
                        
                        table.addHeaderCell(headerCell1);
                        table.addHeaderCell(headerCell2);
                        table.addHeaderCell(headerCell3);
                        table.addHeaderCell(headerCell4);

                        // Filas de ejercicios de la categoría
                        for (RoutineExercise re : categoryEntry.getValue()) {
                            // Validar y sanitizar el nombre del ejercicio
                            String exerciseName = "N/A";
                            if (re.getExercise() != null && re.getExercise().getName() != null) {
                                exerciseName = re.getExercise().getName();
                                // Reemplazar caracteres problemáticos si los hay
                                exerciseName = exerciseName.replace("\u0000", "");
                            }
                            
                            // Validar series y repeticiones
                            String series = re.getSeries() != null ? re.getSeries().toString() : "N/A";
                            String repetitions = re.getRepetitions() != null ? re.getRepetitions().toString() : "N/A";
                            
                            // Validar y sanitizar notas
                            String notes = "-";
                            if (re.getNote() != null && !re.getNote().trim().isEmpty()) {
                                notes = re.getNote().replace("\u0000", "");
                            }
                            
                            table.addCell(new Cell()
                                    .add(new Paragraph(exerciseName).setFontSize(9))
                                    .setBackgroundColor(new DeviceRgb(245, 245, 245))
                                    .setPadding(5));
                            table.addCell(new Cell()
                                    .add(new Paragraph(series).setFontSize(9))
                                    .setBackgroundColor(new DeviceRgb(245, 245, 245))
                                    .setTextAlignment(TextAlignment.CENTER)
                                    .setPadding(5));
                            table.addCell(new Cell()
                                    .add(new Paragraph(repetitions).setFontSize(9))
                                    .setBackgroundColor(new DeviceRgb(245, 245, 245))
                                    .setTextAlignment(TextAlignment.CENTER)
                                    .setPadding(5));
                            table.addCell(new Cell()
                                    .add(new Paragraph(notes).setFontSize(9))
                                    .setBackgroundColor(new DeviceRgb(245, 245, 245))
                                    .setPadding(5));
                        }

                        document.add(table);
                    }
                }
            } else {
                document.add(new Paragraph("No hay ejercicios en esta rutina").setItalic());
            }
        }

        // Agregar nueva página para instrucciones si es necesario
        if (pdf.getNumberOfPages() > 0) {
            document.add(new com.itextpdf.layout.element.AreaBreak(com.itextpdf.layout.properties.AreaBreakType.NEXT_PAGE));
        }

        // Instrucciones finales
        Paragraph instructionsTitle = new Paragraph("INSTRUCCIONES DE ENTRENAMIENTO")
                .setFontSize(14)
                .setBold()
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginTop(20)
                .setMarginBottom(15);
        document.add(instructionsTitle);

        Paragraph instructions = new Paragraph(
                "• Siga los ejercicios en el orden indicado.\n\n" +
                "• Mantenga los movimientos controlados.\n\n" +
                "• Respire correctamente durante todo el ejercicio.\n\n" +
                "• Manténgase hidratado durante el entrenamiento.\n\n" +
                "• Si presenta mareos o dolor, detenga el ejercicio."
        ).setFontSize(11)
         .setMarginLeft(50)
         .setMarginRight(50);
        document.add(instructions);

            document.close();
            return baos.toByteArray();
        } catch (NullPointerException npe) {
            System.err.println("ERROR: NullPointerException en generación de PDF de rutinas");
            npe.printStackTrace();
            throw new Exception("Error: Datos faltantes en la rutina. Verifica que todos los ejercicios tengan información completa.", npe);
        } catch (Exception e) {
            System.err.println("ERROR: Excepción en generación de PDF de rutinas");
            e.printStackTrace();
            throw new Exception("Error al generar PDF de rutinas: " + e.getMessage(), e);
        } finally {
            if (document != null) {
                try {
                    document.close();
                } catch (Exception e) {
                    System.err.println("Error cerrando documento: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Genera un PDF con una rutina sin cliente asignado (para exportación general desde gestión de rutinas)
     */
    public byte[] generateRoutinePdfWithoutClient(una.force_gym.domain.Routine routine) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfWriter writer = new PdfWriter(baos);
        PdfDocument pdf = new PdfDocument(writer);
        Document document = new Document(pdf);

        // Fecha y hora actuales
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
        SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
        String currentDate = dateFormat.format(new java.util.Date());
        String currentTime = timeFormat.format(new java.util.Date());

        // Header con información del reporte
        Paragraph header = new Paragraph("RUTINA DE ENTRENAMIENTO")
                .setFontSize(18)
                .setBold()
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(5);
        document.add(header);

        // Línea separadora
        com.itextpdf.layout.element.LineSeparator lineSeparator1 = 
            new com.itextpdf.layout.element.LineSeparator(
                new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(0.5f));
        lineSeparator1.setMarginTop(5);
        lineSeparator1.setMarginBottom(10);
        document.add(lineSeparator1);

        // Información del reporte
        Paragraph reportInfo = new Paragraph(
                "Fecha del reporte: " + currentDate + "\n" +
                "Hora del reporte: " + currentTime
        ).setFontSize(10).setMarginBottom(15);
        document.add(reportInfo);

        // Línea separadora
        com.itextpdf.layout.element.LineSeparator lineSeparator2 = 
            new com.itextpdf.layout.element.LineSeparator(
                new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(0.5f));
        lineSeparator2.setMarginBottom(15);
        document.add(lineSeparator2);

        // Nombre de la rutina
        Paragraph routineName = new Paragraph(routine.getName())
                .setFontSize(16)
                .setBold()
                .setMarginTop(10)
                .setMarginBottom(5);
        document.add(routineName);

        // Información de la rutina
        Paragraph routineInfo = new Paragraph(
                "Fecha de creación: " + DATE_FORMAT.format(routine.getDate()) + " | " +
                "Dificultad: " + (routine.getDifficultyRoutine() != null ? 
                    routine.getDifficultyRoutine().getName() : "N/A")
        ).setFontSize(9).setMarginBottom(10);
        document.add(routineInfo);

        // Tabla de ejercicios
        if (routine.getExercises() != null && !routine.getExercises().isEmpty()) {
            
            // Agrupar ejercicios por día
            java.util.Map<Integer, java.util.List<RoutineExercise>> exercisesByDay = new java.util.TreeMap<>();
            for (RoutineExercise re : routine.getExercises()) {
                Integer day = re.getDayNumber() != null ? re.getDayNumber() : 1;
                exercisesByDay.computeIfAbsent(day, k -> new java.util.ArrayList<>()).add(re);
            }

            // Crear sección para cada día
            for (java.util.Map.Entry<Integer, java.util.List<RoutineExercise>> dayEntry : exercisesByDay.entrySet()) {
                Integer dayNumber = dayEntry.getKey();
                DeviceRgb dayColor = DAY_COLORS[(dayNumber - 1) % DAY_COLORS.length];
                
                // Título del día (más grande y destacado)
                Paragraph dayTitle = new Paragraph("DÍA " + dayNumber)
                        .setFontSize(16)
                        .setBold()
                        .setFontColor(dayColor)
                        .setMarginTop(12)
                        .setMarginBottom(2);
                document.add(dayTitle);
                
                // Línea divisoria del día
                com.itextpdf.layout.element.LineSeparator lineSeparator = 
                    new com.itextpdf.layout.element.LineSeparator(
                        new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(2f));
                lineSeparator.setStrokeColor(dayColor);
                lineSeparator.setMarginBottom(8);
                document.add(lineSeparator);

                // Agrupar ejercicios del día por categoría
                java.util.Map<String, java.util.List<RoutineExercise>> exercisesByCategory = new java.util.HashMap<>();
                for (RoutineExercise re : dayEntry.getValue()) {
                    String category = (re.getExercise() != null && 
                                     re.getExercise().getExerciseCategory() != null && 
                                     re.getExercise().getExerciseCategory().getName() != null) 
                            ? re.getExercise().getExerciseCategory().getName() 
                            : "Otros";
                    exercisesByCategory.computeIfAbsent(category, k -> new java.util.ArrayList<>()).add(re);
                }
                
                // Ordenar ejercicios dentro de cada categoría por categoryOrder y luego por id
                for (java.util.List<RoutineExercise> exercises : exercisesByCategory.values()) {
                    exercises.sort((a, b) -> {
                        if (!a.getCategoryOrder().equals(b.getCategoryOrder())) {
                            return a.getCategoryOrder().compareTo(b.getCategoryOrder());
                        }
                        return a.getIdRoutineExercise().compareTo(b.getIdRoutineExercise());
                    });
                }

                // Ordenar categorías por el mínimo categoryOrder de sus ejercicios
                java.util.List<java.util.Map.Entry<String, java.util.List<RoutineExercise>>> sortedCategories = 
                    new java.util.ArrayList<>(exercisesByCategory.entrySet());
                sortedCategories.sort((a, b) -> {
                    Integer minOrderA = a.getValue().stream()
                        .map(RoutineExercise::getCategoryOrder)
                        .min(Integer::compareTo)
                        .orElse(Integer.MAX_VALUE);
                    Integer minOrderB = b.getValue().stream()
                        .map(RoutineExercise::getCategoryOrder)
                        .min(Integer::compareTo)
                        .orElse(Integer.MAX_VALUE);
                    return minOrderA.compareTo(minOrderB);
                });

                // Crear tabla para cada categoría (usando el color del día)
                for (java.util.Map.Entry<String, java.util.List<RoutineExercise>> categoryEntry : sortedCategories) {
                    // Título de la categoría
                    Paragraph categoryTitle = new Paragraph("Categoría: " + categoryEntry.getKey())
                            .setFontSize(12)
                            .setBold()
                            .setFontColor(dayColor)
                            .setMarginTop(8)
                            .setMarginBottom(4)
                            .setMarginLeft(10);
                    document.add(categoryTitle);

                    Table table = new Table(UnitValue.createPercentArray(new float[]{3, 1, 1, 2}))
                            .setWidth(UnitValue.createPercentValue(100))
                            .setMarginLeft(15);

                    // Encabezados con el color del día
                    Cell headerCell1 = new Cell()
                            .add(new Paragraph("Ejercicio").setBold().setFontColor(ColorConstants.WHITE))
                            .setBackgroundColor(dayColor)
                            .setTextAlignment(TextAlignment.CENTER)
                            .setPadding(5);
                    Cell headerCell2 = new Cell()
                            .add(new Paragraph("Series").setBold().setFontColor(ColorConstants.WHITE))
                            .setBackgroundColor(dayColor)
                            .setTextAlignment(TextAlignment.CENTER)
                            .setPadding(5);
                    Cell headerCell3 = new Cell()
                            .add(new Paragraph("Repeticiones").setBold().setFontColor(ColorConstants.WHITE))
                            .setBackgroundColor(dayColor)
                            .setTextAlignment(TextAlignment.CENTER)
                            .setPadding(5);
                    Cell headerCell4 = new Cell()
                            .add(new Paragraph("Notas").setBold().setFontColor(ColorConstants.WHITE))
                            .setBackgroundColor(dayColor)
                            .setTextAlignment(TextAlignment.CENTER)
                            .setPadding(5);
                    
                    table.addHeaderCell(headerCell1);
                    table.addHeaderCell(headerCell2);
                    table.addHeaderCell(headerCell3);
                    table.addHeaderCell(headerCell4);

                    // Filas de ejercicios de la categoría
                    for (RoutineExercise re : categoryEntry.getValue()) {
                        table.addCell(new Cell()
                                .add(new Paragraph(re.getExercise() != null ? re.getExercise().getName() : "N/A").setFontSize(9))
                                .setBackgroundColor(new DeviceRgb(245, 245, 245))
                                .setPadding(5));
                        table.addCell(new Cell()
                                .add(new Paragraph(re.getSeries() != null ? re.getSeries().toString() : "N/A").setFontSize(9))
                                .setBackgroundColor(new DeviceRgb(245, 245, 245))
                                .setTextAlignment(TextAlignment.CENTER)
                                .setPadding(5));
                        table.addCell(new Cell()
                                .add(new Paragraph(re.getRepetitions() != null ? re.getRepetitions().toString() : "N/A").setFontSize(9))
                                .setBackgroundColor(new DeviceRgb(245, 245, 245))
                                .setTextAlignment(TextAlignment.CENTER)
                                .setPadding(5));
                        table.addCell(new Cell()
                                .add(new Paragraph(re.getNote() != null ? re.getNote() : "-").setFontSize(9))
                                .setBackgroundColor(new DeviceRgb(245, 245, 245))
                                .setPadding(5));
                    }

                    document.add(table);
                }
            }
        } else {
            document.add(new Paragraph("No hay ejercicios en esta rutina").setItalic());
        }

        // Agregar nueva página para instrucciones si es necesario
        if (pdf.getNumberOfPages() > 0) {
            document.add(new com.itextpdf.layout.element.AreaBreak(com.itextpdf.layout.properties.AreaBreakType.NEXT_PAGE));
        }

        // Instrucciones finales
        Paragraph instructionsTitle = new Paragraph("INSTRUCCIONES DE ENTRENAMIENTO")
                .setFontSize(14)
                .setBold()
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginTop(20)
                .setMarginBottom(15);
        document.add(instructionsTitle);

        Paragraph instructions = new Paragraph(
                "• Siga los ejercicios en el orden indicado.\n\n" +
                "• Mantenga los movimientos controlados.\n\n" +
                "• Respire correctamente durante todo el ejercicio.\n\n" +
                "• Manténgase hidratado durante el entrenamiento.\n\n" +
                "• Si presenta mareos o dolor, detenga el ejercicio."
        ).setFontSize(11)
         .setMarginLeft(50)
         .setMarginRight(50);
        document.add(instructions);

        document.close();
        return baos.toByteArray();
    }

    /**
     * Genera un PDF con las medidas de un cliente (formato admin landscape)
     */
    public byte[] generateMeasurementsPdf(Client client, List<Measurement> measurements) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfWriter writer = new PdfWriter(baos);
        PdfDocument pdf = new PdfDocument(writer);
        pdf.setDefaultPageSize(PageSize.A4.rotate());
        Document document = new Document(pdf);
        
        // Reducir márgenes para aprovechar espacio
        document.setMargins(20, 20, 20, 20);

        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
        SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");
        String currentDate = dateFormat.format(new java.util.Date());
        String currentTime = timeFormat.format(new java.util.Date());

        DeviceRgb yellowColor = new DeviceRgb(207, 173, 4);
        DeviceRgb greyLineColor = new DeviceRgb(200, 200, 200);

        String clientName = client.getPerson().getName() + " " + 
                           client.getPerson().getFirstLastName() + " " + 
                           client.getPerson().getSecondLastName();

        // HEADER: Título centrado
        Paragraph header = new Paragraph("Reporte de Medidas")
                .setFontSize(14)
                .setBold()
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(5);
        document.add(header);

        // Línea separadora 1
        com.itextpdf.layout.element.LineSeparator line1 = 
            new com.itextpdf.layout.element.LineSeparator(
                new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(0.5f));
        line1.setStrokeColor(greyLineColor);
        line1.setMarginTop(2);
        line1.setMarginBottom(8);
        document.add(line1);

        // Información del reporte
        Paragraph reportInfo = new Paragraph()
                .add("Hecho por: Sistema\n")
                .add("Fecha: " + currentDate + "\n")
                .add("Hora: " + currentTime)
                .setFontSize(10)
                .setMarginBottom(5);
        document.add(reportInfo);

        // Línea separadora 2
        com.itextpdf.layout.element.LineSeparator line2 = 
            new com.itextpdf.layout.element.LineSeparator(
                new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(0.5f));
        line2.setStrokeColor(greyLineColor);
        line2.setMarginBottom(8);
        document.add(line2);

        // DATOS DEL CLIENTE
        Paragraph clientTitle = new Paragraph("DATOS DEL CLIENTE")
                .setFontSize(11)
                .setBold()
                .setMarginBottom(5);
        document.add(clientTitle);

        int age = calculateAge(client.getPerson().getBirthday());
        Float height = measurements.isEmpty() ? 0f : measurements.get(0).getHeight();
        
        Paragraph clientInfo = new Paragraph()
                .add("Nombre: " + clientName + "\n")
                .add("Edad: " + age + " años\n")
                .add("Estatura: " + formatFloat(height) + " cm")
                .setFontSize(10)
                .setMarginBottom(5);
        document.add(clientInfo);

        // Línea separadora 3
        com.itextpdf.layout.element.LineSeparator line3 = 
            new com.itextpdf.layout.element.LineSeparator(
                new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(0.5f));
        line3.setStrokeColor(greyLineColor);
        line3.setMarginBottom(10);
        document.add(line3);

        if (!measurements.isEmpty()) {
            java.util.List<Measurement> sortedMeasurements = new java.util.ArrayList<>(measurements);
            sortedMeasurements.sort((a, b) -> b.getMeasurementDate().compareTo(a.getMeasurementDate()));

            // RESUMEN (si hay más de 1 medida)
            if (sortedMeasurements.size() > 1) {
                Measurement first = sortedMeasurements.get(sortedMeasurements.size() - 1);
                Measurement last = sortedMeasurements.get(0);

                Table summaryTable = new Table(UnitValue.createPercentArray(new float[]{2, 1, 1, 1}))
                        .setWidth(UnitValue.createPercentValue(50))
                        .setMarginBottom(10);

                summaryTable.addHeaderCell(createStyledHeaderCell("RESUMEN", yellowColor, 9));
                summaryTable.addHeaderCell(createStyledHeaderCell("INICIO", yellowColor, 9));
                summaryTable.addHeaderCell(createStyledHeaderCell("ACTUAL", yellowColor, 9));
                summaryTable.addHeaderCell(createStyledHeaderCell("CAMBIO", yellowColor, 9));

                summaryTable.addCell(createStyledDataCell("Peso (kg)", 9));
                summaryTable.addCell(createStyledDataCell(formatFloat(first.getWeight()), 9));
                summaryTable.addCell(createStyledDataCell(formatFloat(last.getWeight()), 9));
                summaryTable.addCell(createStyledDataCell(calcIndicator(first.getWeight(), last.getWeight()), 9));

                summaryTable.addCell(createStyledDataCell("IMC", 9));
                summaryTable.addCell(createStyledDataCell(formatFloat(first.getBmi()), 9));
                summaryTable.addCell(createStyledDataCell(formatFloat(last.getBmi()), 9));
                summaryTable.addCell(createStyledDataCell(calcIndicator(first.getBmi(), last.getBmi()), 9));

                summaryTable.addCell(createStyledDataCell("Masa Muscular (%)", 9));
                summaryTable.addCell(createStyledDataCell(formatFloat(first.getMuscleMass()), 9));
                summaryTable.addCell(createStyledDataCell(formatFloat(last.getMuscleMass()), 9));
                summaryTable.addCell(createStyledDataCell(calcIndicator(first.getMuscleMass(), last.getMuscleMass()), 9));

                summaryTable.addCell(createStyledDataCell("Grasa Corporal (%)", 9));
                summaryTable.addCell(createStyledDataCell(formatFloat(first.getBodyFatPercentage()), 9));
                summaryTable.addCell(createStyledDataCell(formatFloat(last.getBodyFatPercentage()), 9));
                summaryTable.addCell(createStyledDataCell(calcIndicator(first.getBodyFatPercentage(), last.getBodyFatPercentage()), 9));

                document.add(summaryTable);
            }

            // 1. MEDIDAS BÁSICAS Y COMPOSICIÓN
            Paragraph section1Title = new Paragraph("MEDIDAS BÁSICAS Y COMPOSICIÓN")
                    .setFontSize(11)
                    .setBold()
                    .setMarginTop(10)
                    .setMarginBottom(5);
            document.add(section1Title);

            Table basicTable = new Table(UnitValue.createPercentArray(new float[]{1.5f, 1, 1, 1, 1, 1, 1}))
                    .setWidth(UnitValue.createPercentValue(100));

            basicTable.addHeaderCell(createStyledHeaderCell("Fecha", yellowColor, 8));
            basicTable.addHeaderCell(createStyledHeaderCell("Peso (kg)", yellowColor, 8));
            basicTable.addHeaderCell(createStyledHeaderCell("Altura (cm)", yellowColor, 8));
            basicTable.addHeaderCell(createStyledHeaderCell("IMC", yellowColor, 8));
            basicTable.addHeaderCell(createStyledHeaderCell("Masa Musc. (%)", yellowColor, 8));
            basicTable.addHeaderCell(createStyledHeaderCell("Grasa Corp. (%)", yellowColor, 8));
            basicTable.addHeaderCell(createStyledHeaderCell("Grasa Visc. (%)", yellowColor, 8));

            boolean alternate = false;
            for (Measurement m : sortedMeasurements) {
                DeviceRgb bgColor = alternate ? new DeviceRgb(245, 245, 245) : new DeviceRgb(255, 255, 255);
                basicTable.addCell(createStripedDataCell(DATE_FORMAT.format(m.getMeasurementDate()), bgColor, 8));
                basicTable.addCell(createStripedDataCell(formatFloat(m.getWeight()), bgColor, 8));
                basicTable.addCell(createStripedDataCell(formatFloat(m.getHeight()), bgColor, 8));
                basicTable.addCell(createStripedDataCell(formatFloat(m.getBmi()), bgColor, 8));
                basicTable.addCell(createStripedDataCell(formatFloat(m.getMuscleMass()), bgColor, 8));
                basicTable.addCell(createStripedDataCell(formatFloat(m.getBodyFatPercentage()), bgColor, 8));
                basicTable.addCell(createStripedDataCell(formatFloat(m.getVisceralFatPercentage()), bgColor, 8));
                alternate = !alternate;
            }

            document.add(basicTable);

            // 2. MEDIDAS DEL TORSO
            Paragraph section2Title = new Paragraph("MEDIDAS DEL TORSO")
                    .setFontSize(11)
                    .setBold()
                    .setMarginTop(10)
                    .setMarginBottom(5);
            document.add(section2Title);

            Table torsoTable = new Table(UnitValue.createPercentArray(new float[]{2, 1, 1, 1, 1}))
                    .setWidth(UnitValue.createPercentValue(100));

            torsoTable.addHeaderCell(createStyledHeaderCell("Fecha", yellowColor, 8));
            torsoTable.addHeaderCell(createStyledHeaderCell("Pecho (cm)", yellowColor, 8));
            torsoTable.addHeaderCell(createStyledHeaderCell("Espalda (cm)", yellowColor, 8));
            torsoTable.addHeaderCell(createStyledHeaderCell("Cintura (cm)", yellowColor, 8));
            torsoTable.addHeaderCell(createStyledHeaderCell("Cadera (cm)", yellowColor, 8));

            alternate = false;
            for (Measurement m : sortedMeasurements) {
                DeviceRgb bgColor = alternate ? new DeviceRgb(245, 245, 245) : new DeviceRgb(255, 255, 255);
                torsoTable.addCell(createStripedDataCell(DATE_FORMAT.format(m.getMeasurementDate()), bgColor, 8));
                torsoTable.addCell(createStripedDataCell(formatFloat(m.getChestSize()), bgColor, 8));
                torsoTable.addCell(createStripedDataCell(formatFloat(m.getBackSize()), bgColor, 8));
                torsoTable.addCell(createStripedDataCell(formatFloat(m.getWaistSize()), bgColor, 8));
                torsoTable.addCell(createStripedDataCell(formatFloat(m.getHipSize()), bgColor, 8));
                alternate = !alternate;
            }

            document.add(torsoTable);

            // 3. BRAZOS
            Paragraph section3Title = new Paragraph("BRAZOS")
                    .setFontSize(11)
                    .setBold()
                    .setMarginTop(10)
                    .setMarginBottom(5);
            document.add(section3Title);

            Table armTable = new Table(UnitValue.createPercentArray(new float[]{2, 1, 1, 1, 1}))
                    .setWidth(UnitValue.createPercentValue(100));

            armTable.addHeaderCell(createStyledHeaderCell("Fecha", yellowColor, 8));
            armTable.addHeaderCell(createStyledHeaderCell("Brazo Der. (cm)", yellowColor, 8));
            armTable.addHeaderCell(createStyledHeaderCell("Brazo Izq. (cm)", yellowColor, 8));
            armTable.addHeaderCell(createStyledHeaderCell("Antebrazo Der. (cm)", yellowColor, 8));
            armTable.addHeaderCell(createStyledHeaderCell("Antebrazo Izq. (cm)", yellowColor, 8));

            alternate = false;
            for (Measurement m : sortedMeasurements) {
                DeviceRgb bgColor = alternate ? new DeviceRgb(245, 245, 245) : new DeviceRgb(255, 255, 255);
                armTable.addCell(createStripedDataCell(DATE_FORMAT.format(m.getMeasurementDate()), bgColor, 8));
                armTable.addCell(createStripedDataCell(formatFloat(m.getRightArmSize()), bgColor, 8));
                armTable.addCell(createStripedDataCell(formatFloat(m.getLeftArmSize()), bgColor, 8));
                armTable.addCell(createStripedDataCell(formatFloat(m.getRightForeArmSize()), bgColor, 8));
                armTable.addCell(createStripedDataCell(formatFloat(m.getLeftForeArmSize()), bgColor, 8));
                alternate = !alternate;
            }

            document.add(armTable);

            // 4. PIERNAS
            Paragraph section4Title = new Paragraph("PIERNAS")
                    .setFontSize(11)
                    .setBold()
                    .setMarginTop(10)
                    .setMarginBottom(5);
            document.add(section4Title);

            Table legTable = new Table(UnitValue.createPercentArray(new float[]{2, 1, 1, 1, 1}))
                    .setWidth(UnitValue.createPercentValue(100));

            legTable.addHeaderCell(createStyledHeaderCell("Fecha", yellowColor, 8));
            legTable.addHeaderCell(createStyledHeaderCell("Pierna Der. (cm)", yellowColor, 8));
            legTable.addHeaderCell(createStyledHeaderCell("Pierna Izq. (cm)", yellowColor, 8));
            legTable.addHeaderCell(createStyledHeaderCell("Pantorrilla Der. (cm)", yellowColor, 8));
            legTable.addHeaderCell(createStyledHeaderCell("Pantorrilla Izq. (cm)", yellowColor, 8));

            alternate = false;
            for (Measurement m : sortedMeasurements) {
                DeviceRgb bgColor = alternate ? new DeviceRgb(245, 245, 245) : new DeviceRgb(255, 255, 255);
                legTable.addCell(createStripedDataCell(DATE_FORMAT.format(m.getMeasurementDate()), bgColor, 8));
                legTable.addCell(createStripedDataCell(formatFloat(m.getRightLegSize()), bgColor, 8));
                legTable.addCell(createStripedDataCell(formatFloat(m.getLeftLegSize()), bgColor, 8));
                legTable.addCell(createStripedDataCell(formatFloat(m.getRightCalfSize()), bgColor, 8));
                legTable.addCell(createStripedDataCell(formatFloat(m.getLeftCalfSize()), bgColor, 8));
                alternate = !alternate;
            }

            document.add(legTable);

            // Mensaje motivacional
            String[] motivationalMessages = {
                "¡Sigue así! La constancia es la clave del éxito.",
                "Cada pequeño esfuerzo te acerca más a tu mejor versión.",
                "Tu disciplina está dando resultados. No te detengas.",
                "El progreso es lento, pero seguro. ¡Excelente trabajo!"
            };
            String message = motivationalMessages[(int) (Math.random() * motivationalMessages.length)];

            Paragraph motivationalMsg = new Paragraph(message)
                    .setFontSize(11)
                    .setItalic()
                    .setTextAlignment(TextAlignment.CENTER)
                    .setMarginTop(15);
            document.add(motivationalMsg);

            // Nueva página para tabla de referencias
            document.add(new AreaBreak(AreaBreakType.NEXT_PAGE));

            Paragraph refTitle = new Paragraph("TABLA DE REFERENCIAS")
                    .setFontSize(14)
                    .setBold()
                    .setTextAlignment(TextAlignment.CENTER)
                    .setMarginBottom(15);
            document.add(refTitle);

            // Tabla de referencias
            Table refTable = new Table(UnitValue.createPercentArray(new float[]{1.5f, 1, 1, 1, 1}))
                    .setWidth(UnitValue.createPercentValue(70));

            DeviceRgb refHeaderColor = new DeviceRgb(230, 230, 230);
            DeviceRgb refLabelColor = new DeviceRgb(242, 242, 242);
            
            refTable.addHeaderCell(createReferenceHeaderCell("", refHeaderColor));
            refTable.addHeaderCell(createReferenceHeaderCell("BAJO", refHeaderColor));
            refTable.addHeaderCell(createReferenceHeaderCell("NORMAL", refHeaderColor));
            refTable.addHeaderCell(createReferenceHeaderCell("ELEVADO", refHeaderColor));
            refTable.addHeaderCell(createReferenceHeaderCell("MUY ELEVADO", refHeaderColor));

            String[][] referenceData = {
                {"IMC", "<18.5", "18.5 a 25", "25 a 30", "30 o +"},
                {"VISCERAL", "", "<9", "10 a 14", "15 o +"},
                {"GRASA C", "FEM / MAS", "FEM / MAS", "FEM / MAS", "FEM / MAS"},
                {"20-39", "<21 / <8", "21-22.9 / 8-19.9", "33-38.9 / 20-24.9", ">39 / >25"},
                {"40-59", "<23 / <11", "23-33.9 / 11-21.9", "34-39.9 / 22-24.9", ">40 / >28"},
                {"60-79", "<24 / <13", "24-35.9 / 13-24.9", "36-41.9 / 25-29.9", ">42 / >30"},
                {"M.M", "FEM / MAS", "FEM / MAS", "FEM / MAS", "FEM / MAS"},
                {"18-39", "<24.3 / <33.3", "24.3-30.3 / 33.3-39.3", "30.4-35.3 / 39.4-44", ">35.4 / >44.1"},
                {"40-59", "<24.1 / <33.1", "24.1-30.1 / 33.1-39.1", "30.2-35.1 / 39.2-43.8", ">35.2 / >43.9"},
                {"60-80", "<23.9 / <32.9", "23.9-29.9 / 32.9-38.9", "30-34.9 / 39-43.6", ">35 / >43.7"}
            };

            for (String[] rowData : referenceData) {
                refTable.addCell(createReferenceLabelCell(rowData[0], refLabelColor));
                for (int i = 1; i < rowData.length; i++) {
                    refTable.addCell(createReferenceDataCell(rowData[i]));
                }
            }

            document.add(refTable);

        } else {
            document.add(new Paragraph("No hay medidas registradas para este cliente.")
                    .setItalic()
                    .setTextAlignment(TextAlignment.CENTER)
                    .setMarginTop(30)
                    .setFontColor(new DeviceRgb(128, 128, 128)));
        }

        document.close();
        return baos.toByteArray();
    }

    private Cell createStyledHeaderCell(String text, DeviceRgb color, int fontSize) {
        return new Cell()
                .add(new Paragraph(text).setBold().setFontColor(ColorConstants.BLACK).setFontSize(fontSize))
                .setBackgroundColor(color)
                .setTextAlignment(TextAlignment.CENTER)
                .setVerticalAlignment(VerticalAlignment.MIDDLE)
                .setPadding(2);
    }

    private Cell createStyledDataCell(String text, int fontSize) {
        return new Cell()
                .add(new Paragraph(text != null ? text : "N/A").setFontSize(fontSize))
                .setTextAlignment(TextAlignment.CENTER)
                .setVerticalAlignment(VerticalAlignment.MIDDLE)
                .setPadding(2);
    }

    private Cell createStripedDataCell(String text, DeviceRgb bgColor, int fontSize) {
        return new Cell()
                .add(new Paragraph(text != null ? text : "N/A").setFontSize(fontSize))
                .setBackgroundColor(bgColor)
                .setTextAlignment(TextAlignment.CENTER)
                .setVerticalAlignment(VerticalAlignment.MIDDLE)
                .setPadding(2);
    }

    private Cell createReferenceHeaderCell(String text, DeviceRgb color) {
        return new Cell()
                .add(new Paragraph(text).setBold().setFontSize(7))
                .setBackgroundColor(color)
                .setTextAlignment(TextAlignment.CENTER)
                .setVerticalAlignment(VerticalAlignment.MIDDLE)
                .setPadding(1)
                .setBorder(new com.itextpdf.layout.borders.SolidBorder(ColorConstants.BLACK, 0.5f));
    }

    private Cell createReferenceLabelCell(String text, DeviceRgb color) {
        return new Cell()
                .add(new Paragraph(text).setBold().setFontSize(7))
                .setBackgroundColor(color)
                .setTextAlignment(TextAlignment.CENTER)
                .setVerticalAlignment(VerticalAlignment.MIDDLE)
                .setPadding(1)
                .setBorder(new com.itextpdf.layout.borders.SolidBorder(ColorConstants.BLACK, 0.5f));
    }

    private Cell createReferenceDataCell(String text) {
        return new Cell()
                .add(new Paragraph(text != null ? text : "").setFontSize(7))
                .setTextAlignment(TextAlignment.CENTER)
                .setVerticalAlignment(VerticalAlignment.MIDDLE)
                .setPadding(1)
                .setBorder(new com.itextpdf.layout.borders.SolidBorder(ColorConstants.BLACK, 0.5f));
    }

    private String calcIndicator(Float start, Float end) {
        if (start == null || end == null) return "—";
        float diff = end - start;
        if (Math.abs(diff) < 0.01) return "—";
        String formatted = String.format("%.1f", diff);
        if (diff > 0) {
            return "▲ +" + formatted;
        } else {
            return "▼ " + formatted;
        }
    }

    private int calculateAge(LocalDate birthDate) {
        if (birthDate == null) return 0;
        return Period.between(birthDate, LocalDate.now()).getYears();
    }

    private String formatFloat(Float value) {
        if (value == null) return "N/A";
        // Si el valor es un número entero, mostrarlo sin decimales
        if (value == value.intValue()) {
            return String.valueOf(value.intValue());
        }
        // Si tiene decimales, mostrar con 2 decimales
        return String.format("%.2f", value);
    }
}

