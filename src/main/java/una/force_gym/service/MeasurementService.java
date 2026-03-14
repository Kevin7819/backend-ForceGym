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
}
