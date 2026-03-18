package una.force_gym.service;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.*;
import org.springframework.stereotype.Service;

import una.force_gym.domain.Client;
import una.force_gym.domain.Measurement;

import java.io.ByteArrayOutputStream;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.Period;
import java.util.List;

@Service
public class ExcelGeneratorService {

    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("dd/MM/yyyy");
    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("HH:mm:ss");

    /**
     * Genera un archivo Excel con las medidas de un cliente (formato admin)
     */
    public byte[] generateMeasurementsExcel(Client client, List<Measurement> measurements) throws Exception {
        XSSFWorkbook workbook = new XSSFWorkbook();
        String clientName = client.getPerson().getName() + " " + 
                           client.getPerson().getFirstLastName() + " " + 
                           client.getPerson().getSecondLastName();
        XSSFSheet sheet = workbook.createSheet("Reporte Medidas - " + clientName);

        String currentDate = DATE_FORMAT.format(new java.util.Date());
        String currentTime = TIME_FORMAT.format(new java.util.Date());

        int currentRow = 0;

        // Fila 1: Espacio para logo (A1:C1) y Título (D1:S1)
        Row titleRow = sheet.createRow(currentRow);
        titleRow.setHeightInPoints(50);
        
        // Título centrado en D1:S1
        sheet.addMergedRegion(new org.apache.poi.ss.util.CellRangeAddress(0, 0, 3, 18));
        Cell titleCell = titleRow.createCell(3);
        titleCell.setCellValue("Reporte de Medidas - " + clientName);
        CellStyle titleStyle = workbook.createCellStyle();
        Font titleFont = workbook.createFont();
        titleFont.setFontHeightInPoints((short) 16);
        titleFont.setBold(true);
        titleFont.setFontName("Arial");
        titleStyle.setFont(titleFont);
        titleStyle.setAlignment(HorizontalAlignment.CENTER);
        titleStyle.setVerticalAlignment(VerticalAlignment.CENTER);
        titleCell.setCellStyle(titleStyle);

        currentRow++; // Fila 2: vacía
        currentRow++; // Fila 3

        // A3, A4, A5: Hecho por, Fecha, Hora
        CellStyle infoStyle = workbook.createCellStyle();
        Font infoFont = workbook.createFont();
        infoFont.setFontHeightInPoints((short) 11);
        infoFont.setItalic(true);
        infoFont.setFontName("Arial");
        infoStyle.setFont(infoFont);
        infoStyle.setVerticalAlignment(VerticalAlignment.CENTER);

        Row hechoRow = sheet.createRow(currentRow++);
        Cell hechoCell = hechoRow.createCell(0);
        hechoCell.setCellValue("Hecho por: Sistema");
        hechoCell.setCellStyle(infoStyle);

        Row fechaRow = sheet.createRow(currentRow++);
        Cell fechaCell = fechaRow.createCell(0);
        fechaCell.setCellValue("Fecha: " + currentDate);
        fechaCell.setCellStyle(infoStyle);

        Row horaRow = sheet.createRow(currentRow++);
        Cell horaCell = horaRow.createCell(0);
        horaCell.setCellValue("Hora: " + currentTime);
        horaCell.setCellStyle(infoStyle);

        currentRow++; // Fila 7

        // Datos del cliente
        CellStyle clientStyle = workbook.createCellStyle();
        Font clientFont = workbook.createFont();
        clientFont.setFontHeightInPoints((short) 11);
        clientFont.setBold(true);
        clientFont.setFontName("Arial");
        clientStyle.setFont(clientFont);

        CellStyle clientDataStyle = workbook.createCellStyle();
        Font clientDataFont = workbook.createFont();
        clientDataFont.setFontHeightInPoints((short) 11);
        clientDataFont.setFontName("Arial");
        clientDataStyle.setFont(clientDataFont);

        Row clientRow = sheet.createRow(currentRow++);
        Cell clientCell = clientRow.createCell(0);
        clientCell.setCellValue("Cliente: " + clientName);
        clientCell.setCellStyle(clientStyle);

        int age = calculateAge(client.getPerson().getBirthday());
        Row ageRow = sheet.createRow(currentRow++);
        Cell ageCell = ageRow.createCell(0);
        ageCell.setCellValue("Edad: " + age + " años");
        ageCell.setCellStyle(clientDataStyle);

        Float height = measurements.isEmpty() ? 0f : measurements.get(0).getHeight();
        Row heightRow = sheet.createRow(currentRow++);
        Cell heightCell = heightRow.createCell(0);
        heightCell.setCellValue("Estatura: " + formatFloat(height) + " cm");
        heightCell.setCellStyle(clientDataStyle);

        currentRow++; // Línea separadora
        Row separatorRow = sheet.createRow(currentRow++);
        sheet.addMergedRegion(new org.apache.poi.ss.util.CellRangeAddress(
                currentRow - 1, currentRow - 1, 0, 18));
        Cell separatorCell = separatorRow.createCell(0);
        CellStyle separatorStyle = workbook.createCellStyle();
        separatorStyle.setBorderBottom(BorderStyle.THIN);
        separatorStyle.setBottomBorderColor(IndexedColors.GREY_40_PERCENT.getIndex());
        separatorCell.setCellStyle(separatorStyle);

        currentRow++; // Espacio

        if (!measurements.isEmpty()) {
            // Ordenar medidas por fecha (más reciente primero)
            List<Measurement> sortedMeasurements = new java.util.ArrayList<>(measurements);
            sortedMeasurements.sort((a, b) -> b.getMeasurementDate().compareTo(a.getMeasurementDate()));

            // RESUMEN (si hay más de 1 medida)
            if (sortedMeasurements.size() > 1) {
                Measurement first = sortedMeasurements.get(sortedMeasurements.size() - 1);
                Measurement last = sortedMeasurements.get(0);

                // Headers del resumen
                Row resumenHeaderRow = sheet.createRow(currentRow++);
                String[] resumenHeaders = {"RESUMEN", "INICIO", "ACTUAL", "CAMBIO"};
                CellStyle resumenHeaderStyle = workbook.createCellStyle();
                Font resumenHeaderFont = workbook.createFont();
                resumenHeaderFont.setBold(true);
                resumenHeaderFont.setFontName("Arial");
                resumenHeaderStyle.setFont(resumenHeaderFont);
                resumenHeaderStyle.setAlignment(HorizontalAlignment.CENTER);
                
                for (int i = 0; i < resumenHeaders.length; i++) {
                    Cell cell = resumenHeaderRow.createCell(i);
                    cell.setCellValue(resumenHeaders[i]);
                    cell.setCellStyle(resumenHeaderStyle);
                }

                // Datos del resumen
                CellStyle resumenDataStyle = workbook.createCellStyle();
                Font resumenDataFont = workbook.createFont();
                resumenDataFont.setFontHeightInPoints((short) 11);
                resumenDataFont.setFontName("Arial");
                resumenDataStyle.setFont(resumenDataFont);
                resumenDataStyle.setAlignment(HorizontalAlignment.CENTER);

                String[][] resumenData = {
                    {"Peso (kg)", formatFloat(first.getWeight()), formatFloat(last.getWeight()), 
                     calcIndicator(first.getWeight(), last.getWeight())},
                    {"IMC", formatFloat(first.getBmi()), formatFloat(last.getBmi()), 
                     calcIndicator(first.getBmi(), last.getBmi())},
                    {"Masa Muscular (%)", formatFloat(first.getMuscleMass()), formatFloat(last.getMuscleMass()), 
                     calcIndicator(first.getMuscleMass(), last.getMuscleMass())},
                    {"Grasa Corporal (%)", formatFloat(first.getBodyFatPercentage()), formatFloat(last.getBodyFatPercentage()), 
                     calcIndicator(first.getBodyFatPercentage(), last.getBodyFatPercentage())}
                };

                for (String[] rowData : resumenData) {
                    Row resumenRow = sheet.createRow(currentRow++);
                    for (int i = 0; i < rowData.length; i++) {
                        Cell cell = resumenRow.createCell(i);
                        cell.setCellValue(rowData[i]);
                        cell.setCellStyle(resumenDataStyle);
                    }
                }

                currentRow += 2; // Dos espacios
            }

            // TABLA PRINCIPAL CON TODAS LAS COLUMNAS
            Row headerRow = sheet.createRow(currentRow++);
            headerRow.setHeightInPoints(25);

            String[] tableHeaders = {
                "Fecha", "Peso (kg)", "Altura (cm)", "IMC", "Masa Musc. (%)", "Grasa Corp. (%)", "Grasa Visc. (%)",
                "Pecho (cm)", "Espalda (cm)", "Cintura (cm)", "Cadera (cm)",
                "Brazo Der. (cm)", "Brazo Izq. (cm)", "Antebrazo Der. (cm)", "Antebrazo Izq. (cm)",
                "Pierna Der. (cm)", "Pierna Izq. (cm)", "Pantorrilla Der. (cm)", "Pantorrilla Izq. (cm)"
            };

            CellStyle headerStyle = workbook.createCellStyle();
            Font headerFont = workbook.createFont();
            headerFont.setBold(true);
            headerFont.setFontHeightInPoints((short) 12);
            headerFont.setFontName("Arial");
            headerFont.setColor(IndexedColors.BLACK.getIndex());
            headerStyle.setFont(headerFont);
            headerStyle.setFillForegroundColor(new XSSFColor(new byte[]{(byte) 207, (byte) 173, 4}, null));
            headerStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
            headerStyle.setAlignment(HorizontalAlignment.CENTER);
            headerStyle.setVerticalAlignment(VerticalAlignment.CENTER);
            headerStyle.setWrapText(true);
            headerStyle.setBorderTop(BorderStyle.THIN);
            headerStyle.setBorderBottom(BorderStyle.THIN);
            headerStyle.setBorderLeft(BorderStyle.THIN);
            headerStyle.setBorderRight(BorderStyle.THIN);

            for (int i = 0; i < tableHeaders.length; i++) {
                Cell cell = headerRow.createCell(i);
                cell.setCellValue(tableHeaders[i]);
                cell.setCellStyle(headerStyle);
            }

            // Datos de la tabla
            CellStyle dataStyle = workbook.createCellStyle();
            Font dataFont = workbook.createFont();
            dataFont.setFontHeightInPoints((short) 11);
            dataFont.setFontName("Arial");
            dataStyle.setFont(dataFont);
            dataStyle.setAlignment(HorizontalAlignment.CENTER);
            dataStyle.setVerticalAlignment(VerticalAlignment.CENTER);
            dataStyle.setWrapText(true);
            dataStyle.setBorderTop(BorderStyle.THIN);
            dataStyle.setBorderBottom(BorderStyle.THIN);
            dataStyle.setBorderLeft(BorderStyle.THIN);
            dataStyle.setBorderRight(BorderStyle.THIN);

            for (Measurement m : sortedMeasurements) {
                Row dataRow = sheet.createRow(currentRow++);
                int col = 0;
                
                // Fecha
                Cell cell0 = dataRow.createCell(col++);
                cell0.setCellValue(DATE_FORMAT.format(m.getMeasurementDate()));
                cell0.setCellStyle(dataStyle);
                
                // Medidas básicas
                Cell cell1 = dataRow.createCell(col++);
                cell1.setCellValue(formatFloat(m.getWeight()));
                cell1.setCellStyle(dataStyle);
                
                Cell cell2 = dataRow.createCell(col++);
                cell2.setCellValue(formatFloat(m.getHeight()));
                cell2.setCellStyle(dataStyle);
                
                Cell cell3 = dataRow.createCell(col++);
                cell3.setCellValue(formatFloat(m.getBmi()));
                cell3.setCellStyle(dataStyle);
                
                Cell cell4 = dataRow.createCell(col++);
                cell4.setCellValue(formatFloat(m.getMuscleMass()));
                cell4.setCellStyle(dataStyle);
                
                Cell cell5 = dataRow.createCell(col++);
                cell5.setCellValue(formatFloat(m.getBodyFatPercentage()));
                cell5.setCellStyle(dataStyle);
                
                Cell cell6 = dataRow.createCell(col++);
                cell6.setCellValue(formatFloat(m.getVisceralFatPercentage()));
                cell6.setCellStyle(dataStyle);
                
                // Torso
                Cell cell7 = dataRow.createCell(col++);
                cell7.setCellValue(formatFloat(m.getChestSize()));
                cell7.setCellStyle(dataStyle);
                
                Cell cell8 = dataRow.createCell(col++);
                cell8.setCellValue(formatFloat(m.getBackSize()));
                cell8.setCellStyle(dataStyle);
                
                Cell cell9 = dataRow.createCell(col++);
                cell9.setCellValue(formatFloat(m.getWaistSize()));
                cell9.setCellStyle(dataStyle);
                
                Cell cell10 = dataRow.createCell(col++);
                cell10.setCellValue(formatFloat(m.getHipSize()));
                cell10.setCellStyle(dataStyle);
                
                // Brazos
                Cell cell11 = dataRow.createCell(col++);
                cell11.setCellValue(formatFloat(m.getRightArmSize()));
                cell11.setCellStyle(dataStyle);
                
                Cell cell12 = dataRow.createCell(col++);
                cell12.setCellValue(formatFloat(m.getLeftArmSize()));
                cell12.setCellStyle(dataStyle);
                
                Cell cell13 = dataRow.createCell(col++);
                cell13.setCellValue(formatFloat(m.getRightForeArmSize()));
                cell13.setCellStyle(dataStyle);
                
                Cell cell14 = dataRow.createCell(col++);
                cell14.setCellValue(formatFloat(m.getLeftForeArmSize()));
                cell14.setCellStyle(dataStyle);
                
                // Piernas
                Cell cell15 = dataRow.createCell(col++);
                cell15.setCellValue(formatFloat(m.getRightLegSize()));
                cell15.setCellStyle(dataStyle);
                
                Cell cell16 = dataRow.createCell(col++);
                cell16.setCellValue(formatFloat(m.getLeftLegSize()));
                cell16.setCellStyle(dataStyle);
                
                Cell cell17 = dataRow.createCell(col++);
                cell17.setCellValue(formatFloat(m.getRightCalfSize()));
                cell17.setCellStyle(dataStyle);
                
                Cell cell18 = dataRow.createCell(col++);
                cell18.setCellValue(formatFloat(m.getLeftCalfSize()));
                cell18.setCellStyle(dataStyle);
            }

            currentRow += 2; // Dos espacios

            // MENSAJE MOTIVACIONAL
            String[] motivationalMessages = {
                "¡Sigue así! La constancia es la clave del éxito.",
                "Cada pequeño esfuerzo te acerca más a tu mejor versión.",
                "Tu disciplina está dando resultados. No te detengas.",
                "El progreso es lento, pero seguro. ¡Excelente trabajo!"
            };
            String message = motivationalMessages[(int) (Math.random() * motivationalMessages.length)];

            Row messageRow = sheet.createRow(currentRow++);
            messageRow.setHeightInPoints(30);
            sheet.addMergedRegion(new org.apache.poi.ss.util.CellRangeAddress(
                    currentRow - 1, currentRow - 1, 0, 18));
            Cell messageCell = messageRow.createCell(0);
            messageCell.setCellValue(message);
            
            CellStyle messageStyle = workbook.createCellStyle();
            Font messageFont = workbook.createFont();
            messageFont.setItalic(true);
            messageFont.setBold(true);
            messageFont.setFontHeightInPoints((short) 12);
            messageFont.setFontName("Arial");
            messageStyle.setFont(messageFont);
            messageStyle.setAlignment(HorizontalAlignment.CENTER);
            messageStyle.setVerticalAlignment(VerticalAlignment.CENTER);
            messageStyle.setWrapText(true);
            messageCell.setCellStyle(messageStyle);

            currentRow += 3; // Tres espacios

            // TABLA DE REFERENCIAS
            Row refHeaderRow = sheet.createRow(currentRow++);
            String[] referenceHeaders = {"", "BAJO", "NORMAL", "ELEVADO", "MUY ELEVADO"};
            
            CellStyle refHeaderStyle = workbook.createCellStyle();
            Font refHeaderFont = workbook.createFont();
            refHeaderFont.setBold(true);
            refHeaderFont.setFontHeightInPoints((short) 10);
            refHeaderFont.setFontName("Arial");
            refHeaderStyle.setFont(refHeaderFont);
            refHeaderStyle.setAlignment(HorizontalAlignment.CENTER);
            refHeaderStyle.setVerticalAlignment(VerticalAlignment.CENTER);

            for (int i = 0; i < referenceHeaders.length; i++) {
                Cell cell = refHeaderRow.createCell(i);
                cell.setCellValue(referenceHeaders[i]);
                cell.setCellStyle(refHeaderStyle);
            }

            // Datos de referencia
            CellStyle refDataStyle = workbook.createCellStyle();
            Font refDataFont = workbook.createFont();
            refDataFont.setFontHeightInPoints((short) 9);
            refDataFont.setFontName("Arial");
            refDataStyle.setFont(refDataFont);
            refDataStyle.setAlignment(HorizontalAlignment.CENTER);
            refDataStyle.setVerticalAlignment(VerticalAlignment.CENTER);
            refDataStyle.setWrapText(true);

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
                Row refRow = sheet.createRow(currentRow++);
                for (int i = 0; i < rowData.length; i++) {
                    Cell cell = refRow.createCell(i);
                    cell.setCellValue(rowData[i]);
                    cell.setCellStyle(refDataStyle);
                }
            }

        } else {
            Row noDataRow = sheet.createRow(currentRow++);
            Cell noDataCell = noDataRow.createCell(0);
            noDataCell.setCellValue("No hay medidas registradas");
            sheet.addMergedRegion(new org.apache.poi.ss.util.CellRangeAddress(
                    currentRow - 1, currentRow - 1, 0, 4));
        }

        // Ajustar ancho de columnas
        for (int i = 0; i < 19; i++) {
            sheet.setColumnWidth(i, 14 * 256); // 14 caracteres de ancho
        }

        // Escribir a ByteArrayOutputStream
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        workbook.write(baos);
        workbook.close();

        return baos.toByteArray();
    }

    private int calculateAge(LocalDate birthDate) {
        if (birthDate == null) return 0;
        return Period.between(birthDate, LocalDate.now()).getYears();
    }

    private String formatFloat(Float value) {
        if (value == null) return "N/A";
        return String.format("%.1f", value);
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
}
