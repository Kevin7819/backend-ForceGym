package una.force_gym.service;

import java.time.LocalDate;
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
import una.force_gym.domain.EconomicIncome;
import una.force_gym.repository.EconomicIncomeRepository;

@Service
public class EconomicIncomeService {

    @Autowired
    private EconomicIncomeRepository economicIncomeRepo;

    @PersistenceContext
    private EntityManager entityManager;

    public Map<String, Object> getEconomicIncomes(
        int page, 
        int size, int searchType, 
        String searchTerm, 
        String orderBy, 
        String directionOrderBy, 
        String filterByStatus,
        Long filterByAmountRangeMin,
        Long filterByAmountRangeMax,
        LocalDate  filterByDateRangeStart,
        LocalDate  filterByDateRangeEnd,
        int filterByMeanOfPayment,
        int filterByClientType
    ) {
            
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetEconomicIncome", EconomicIncome.class);
        
        // Parámetros de entrada
        query.registerStoredProcedureParameter("p_page", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_limit", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchType", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchTerm", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_orderBy", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_directionOrderBy", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByStatus", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByAmountRangeMin", Float.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByAmountRangeMax", Float.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByDateRangeStart", LocalDate.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByDateRangeEnd", LocalDate.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByMeanOfPayment", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByClientType", Integer.class, ParameterMode.IN);

        // Parámetro de salida
        query.registerStoredProcedureParameter("p_totalRecords", Integer.class, ParameterMode.OUT);

        // Setear valores
        query.setParameter("p_page", page);
        query.setParameter("p_limit", size);
        query.setParameter("p_searchType", searchType);
        query.setParameter("p_searchTerm", searchTerm);
        query.setParameter("p_orderBy", orderBy);
        query.setParameter("p_directionOrderBy", directionOrderBy);
        query.setParameter("p_filterByStatus", filterByStatus);
        query.setParameter("p_filterByAmountRangeMin", filterByAmountRangeMin);
        query.setParameter("p_filterByAmountRangeMax", filterByAmountRangeMax);
        query.setParameter("p_filterByDateRangeStart", filterByDateRangeStart);
        query.setParameter("p_filterByDateRangeEnd", filterByDateRangeEnd);
        query.setParameter("p_filterByMeanOfPayment", filterByMeanOfPayment);
        query.setParameter("p_filterByClientType", filterByClientType);

        // Ejecutar procedimiento
        query.execute();

        // Obtener los resultados
        List<?> rawResults = query.getResultList();
        List<EconomicIncome> incomes = rawResults.stream()
            .filter(EconomicIncome.class::isInstance) 
            .map(EconomicIncome.class::cast)         
            .collect(Collectors.toList());

        Integer totalRecords = (Integer) query.getOutputParameterValue("p_totalRecords");

        // Mapear respuesta
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("economicIncomes", incomes);
        responseData.put("totalRecords", totalRecords);
        
        return responseData;
    }

    public Map<String, Object> getAllEconomicIncomes(
        String filterByStatus,
        Long filterByAmountRangeMin,
        Long filterByAmountRangeMax,
        LocalDate  filterByDateRangeStart,
        LocalDate  filterByDateRangeEnd,
        int filterByMeanOfPayment
    ) {
            
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetAllEconomicIncomes", EconomicIncome.class);
        
        query.registerStoredProcedureParameter("p_filterByStatus", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByAmountRangeMin", Float.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByAmountRangeMax", Float.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByDateRangeStart", LocalDate.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByDateRangeEnd", LocalDate.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByMeanOfPayment", Integer.class, ParameterMode.IN);
        // Setear valores
        query.setParameter("p_filterByStatus", filterByStatus);
        query.setParameter("p_filterByAmountRangeMin", filterByAmountRangeMin);
        query.setParameter("p_filterByAmountRangeMax", filterByAmountRangeMax);
        query.setParameter("p_filterByDateRangeStart", filterByDateRangeStart);
        query.setParameter("p_filterByDateRangeEnd", filterByDateRangeEnd);
        query.setParameter("p_filterByMeanOfPayment", filterByMeanOfPayment);
        // Ejecutar procedimiento
        query.execute();

        // Obtener los resultados
        List<?> rawResults = query.getResultList();
        List<EconomicIncome> incomes = rawResults.stream()
            .filter(EconomicIncome.class::isInstance) 
            .map(EconomicIncome.class::cast)         
            .collect(Collectors.toList());

        // Mapear respuesta
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("economicIncomes", incomes);        
        return responseData;
    }

    @Transactional
    public int addEconomicIncome(Long pIdClient, LocalDate pRegistrationDate, String pVoucherNumber, String pDetail, Long pIdMeanOfPayment, Float pAmount, Long pIdActivityType, Long pDelayDays, Long pLoggedIdUser){
        return economicIncomeRepo.addEconomicIncome(pIdClient, pRegistrationDate, pVoucherNumber, pDetail, pIdMeanOfPayment, pAmount, pIdActivityType, pDelayDays, pLoggedIdUser);
    }

    @Transactional
    public int updateEconomicIncome(Long pIdEconomicIncome, Long pIdClient, LocalDate pRegistrationDate, String pVoucherNumber, String pDetail, Long pIdMeanOfPayment, Float pAmount, Long pIdActivityType, Long pDelayDays, Long pIsDeleted, Long pLoggedIdUser){
        return economicIncomeRepo.updateEconomicIncome(pIdEconomicIncome, pIdClient, pRegistrationDate, pVoucherNumber, pDetail, pIdMeanOfPayment, pAmount, pIdActivityType, pDelayDays, pIsDeleted, pLoggedIdUser);
    }

    @Transactional
    public int deleteEconomicIncome(Long pIdEconomicIncome, Long pLoggedIdUser){
        return economicIncomeRepo.deleteEconomicIncome(pIdEconomicIncome, pLoggedIdUser);
    }

}
