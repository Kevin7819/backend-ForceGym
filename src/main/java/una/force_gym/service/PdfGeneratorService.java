package una.force_gym.service;

import java.io.ByteArrayOutputStream;
import java.text.SimpleDateFormat;
import java.util.List;

import org.springframework.stereotype.Service;

import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;

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
        PdfWriter writer = new PdfWriter(baos);
        PdfDocument pdf = new PdfDocument(writer);
        Document document = new Document(pdf);

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
     * Genera un PDF con las medidas de un cliente
     */
    public byte[] generateMeasurementsPdf(Client client, List<Measurement> measurements) throws Exception {
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
        Paragraph header = new Paragraph("HISTORIAL DE MEDIDAS CORPORALES")
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

        // Color principal para medidas
        DeviceRgb measurementColor = new DeviceRgb(207, 173, 4); // Amarillo del sistema

        // Si hay medidas, mostrarlas
        if (!measurements.isEmpty()) {
            // Ordenar medidas por fecha (más reciente primero)
            java.util.List<Measurement> sortedMeasurements = new java.util.ArrayList<>(measurements);
            sortedMeasurements.sort((a, b) -> b.getMeasurementDate().compareTo(a.getMeasurementDate()));

            // Iterar sobre las medidas
            for (int i = 0; i < sortedMeasurements.size(); i++) {
                Measurement m = sortedMeasurements.get(i);
                
                // Título de la medición con color
                Paragraph measurementTitle = new Paragraph("MEDICIÓN #" + (i + 1))
                        .setFontSize(14)
                        .setBold()
                        .setFontColor(measurementColor)
                        .setMarginTop(12)
                        .setMarginBottom(2);
                document.add(measurementTitle);
                
                // Fecha de medición
                Paragraph dateInfo = new Paragraph("Fecha: " + DATE_FORMAT.format(m.getMeasurementDate()))
                        .setFontSize(10)
                        .setMarginBottom(8);
                document.add(dateInfo);
                
                // Línea divisoria
                com.itextpdf.layout.element.LineSeparator lineSeparator = 
                    new com.itextpdf.layout.element.LineSeparator(
                        new com.itextpdf.kernel.pdf.canvas.draw.SolidLine(1f));
                lineSeparator.setStrokeColor(measurementColor);
                lineSeparator.setMarginBottom(10);
                document.add(lineSeparator);

                lineSeparator.setStrokeColor(measurementColor);
                lineSeparator.setMarginBottom(10);
                document.add(lineSeparator);

                // Subtítulo: Datos Generales
                Paragraph generalTitle = new Paragraph("Datos Generales")
                        .setFontSize(11)
                        .setBold()
                        .setFontColor(measurementColor)
                        .setMarginBottom(5)
                        .setMarginLeft(5);
                document.add(generalTitle);

                // Tabla de medidas generales con color amarillo
                Table generalTable = new Table(UnitValue.createPercentArray(new float[]{1, 1, 1, 1, 1}))
                        .setWidth(UnitValue.createPercentValue(100))
                        .setMarginLeft(10);

                // Headers con color amarillo
                Cell headerCell1 = new Cell()
                        .add(new Paragraph("Peso (kg)").setBold().setFontColor(ColorConstants.WHITE).setFontSize(9))
                        .setBackgroundColor(measurementColor)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setPadding(5);
                Cell headerCell2 = new Cell()
                        .add(new Paragraph("Altura (cm)").setBold().setFontColor(ColorConstants.WHITE).setFontSize(9))
                        .setBackgroundColor(measurementColor)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setPadding(5);
                Cell headerCell3 = new Cell()
                        .add(new Paragraph("Masa Muscular").setBold().setFontColor(ColorConstants.WHITE).setFontSize(9))
                        .setBackgroundColor(measurementColor)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setPadding(5);
                Cell headerCell4 = new Cell()
                        .add(new Paragraph("% Grasa Corporal").setBold().setFontColor(ColorConstants.WHITE).setFontSize(9))
                        .setBackgroundColor(measurementColor)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setPadding(5);
                Cell headerCell5 = new Cell()
                        .add(new Paragraph("% Grasa Visceral").setBold().setFontColor(ColorConstants.WHITE).setFontSize(9))
                        .setBackgroundColor(measurementColor)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setPadding(5);
                
                generalTable.addHeaderCell(headerCell1);
                generalTable.addHeaderCell(headerCell2);
                generalTable.addHeaderCell(headerCell3);
                generalTable.addHeaderCell(headerCell4);
                generalTable.addHeaderCell(headerCell5);

                generalTable.addCell(createMeasurementCell(formatFloat(m.getWeight())));
                generalTable.addCell(createMeasurementCell(formatFloat(m.getHeight())));
                generalTable.addCell(createMeasurementCell(formatFloat(m.getMuscleMass())));
                generalTable.addCell(createMeasurementCell(formatFloat(m.getBodyFatPercentage())));
                generalTable.addCell(createMeasurementCell(formatFloat(m.getVisceralFatPercentage())));

                document.add(generalTable);

                // Subtítulo: Medidas Corporales
                Paragraph bodyMeasuresTitle = new Paragraph("Medidas Corporales (cm)")
                        .setFontSize(11)
                        .setBold()
                        .setFontColor(measurementColor)
                        .setMarginTop(12)
                        .setMarginBottom(5)
                        .setMarginLeft(5);
                document.add(bodyMeasuresTitle);

                // Tabla de medidas corporales
                Table bodyTable = new Table(UnitValue.createPercentArray(new float[]{1.5f, 1, 1.5f, 1}))
                        .setWidth(UnitValue.createPercentValue(100))
                        .setMarginLeft(10);

                // Headers con color amarillo
                Cell bodyHeader1 = new Cell()
                        .add(new Paragraph("Medida").setBold().setFontColor(ColorConstants.WHITE).setFontSize(9))
                        .setBackgroundColor(measurementColor)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setPadding(5);
                Cell bodyHeader2 = new Cell()
                        .add(new Paragraph("Valor").setBold().setFontColor(ColorConstants.WHITE).setFontSize(9))
                        .setBackgroundColor(measurementColor)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setPadding(5);
                Cell bodyHeader3 = new Cell()
                        .add(new Paragraph("Medida").setBold().setFontColor(ColorConstants.WHITE).setFontSize(9))
                        .setBackgroundColor(measurementColor)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setPadding(5);
                Cell bodyHeader4 = new Cell()
                        .add(new Paragraph("Valor").setBold().setFontColor(ColorConstants.WHITE).setFontSize(9))
                        .setBackgroundColor(measurementColor)
                        .setTextAlignment(TextAlignment.CENTER)
                        .setPadding(5);

                bodyTable.addHeaderCell(bodyHeader1);
                bodyTable.addHeaderCell(bodyHeader2);
                bodyTable.addHeaderCell(bodyHeader3);
                bodyTable.addHeaderCell(bodyHeader4);

                addMeasurementRowStyled(bodyTable, "Pecho", m.getChestSize(), "Cadera", m.getHipSize());
                addMeasurementRowStyled(bodyTable, "Espalda", m.getBackSize(), "Cintura", m.getWaistSize());
                addMeasurementRowStyled(bodyTable, "Pierna Izq.", m.getLeftLegSize(), "Pierna Der.", m.getRightLegSize());
                addMeasurementRowStyled(bodyTable, "Pantorrilla Izq.", m.getLeftCalfSize(), "Pantorrilla Der.", m.getRightCalfSize());
                addMeasurementRowStyled(bodyTable, "Antebrazo Izq.", m.getLeftForeArmSize(), "Antebrazo Der.", m.getRightForeArmSize());
                addMeasurementRowStyled(bodyTable, "Brazo Izq.", m.getLeftArmSize(), "Brazo Der.", m.getRightArmSize());

                document.add(bodyTable);
            }
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

    private Cell createMeasurementCell(String text) {
        return new Cell()
                .add(new Paragraph(text != null ? text : "N/A").setFontSize(9))
                .setBackgroundColor(new DeviceRgb(245, 245, 245))
                .setTextAlignment(TextAlignment.CENTER)
                .setPadding(5);
    }

    private void addMeasurementRowStyled(Table table, String label1, Float value1, String label2, Float value2) {
        table.addCell(new Cell()
                .add(new Paragraph(label1).setFontSize(9))
                .setBackgroundColor(new DeviceRgb(255, 255, 255))
                .setPadding(5));
        table.addCell(new Cell()
                .add(new Paragraph(formatFloat(value1)).setFontSize(9))
                .setBackgroundColor(new DeviceRgb(245, 245, 245))
                .setTextAlignment(TextAlignment.CENTER)
                .setPadding(5));
        table.addCell(new Cell()
                .add(new Paragraph(label2).setFontSize(9))
                .setBackgroundColor(new DeviceRgb(255, 255, 255))
                .setPadding(5));
        table.addCell(new Cell()
                .add(new Paragraph(formatFloat(value2)).setFontSize(9))
                .setBackgroundColor(new DeviceRgb(245, 245, 245))
                .setTextAlignment(TextAlignment.CENTER)
                .setPadding(5));
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
