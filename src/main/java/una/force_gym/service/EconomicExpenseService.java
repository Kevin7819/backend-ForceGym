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
import una.force_gym.domain.EconomicExpense;
import una.force_gym.repository.EconomicExpenseRepository;

@Service
public class EconomicExpenseService {

    @Autowired
    private EconomicExpenseRepository economicExpenseRepo;

    @PersistenceContext
    private EntityManager entityManager;

    public Map<String, Object> getEconomicExpenses(
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
        int filterByCategory
    ) {
            
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetEconomicExpense", EconomicExpense.class);
        
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
        query.registerStoredProcedureParameter("p_filterByCategory", Integer.class, ParameterMode.IN);

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
        query.setParameter("p_filterByCategory", filterByCategory);


        // Ejecutar procedimiento
        query.execute();

        // Obtener los resultados
        List<?> rawResults = query.getResultList();
        List<EconomicExpense> expenses = rawResults.stream()
            .filter(EconomicExpense.class::isInstance) 
            .map(EconomicExpense.class::cast)         
            .collect(Collectors.toList());

        Integer totalRecords = (Integer) query.getOutputParameterValue("p_totalRecords");

        // Mapear respuesta
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("economicExpenses", expenses);
        responseData.put("totalRecords", totalRecords);
        
        return responseData;
    }
    
    public Map<String, Object> getAllEconomicExpenses(
        String filterByStatus,
        Long filterByAmountRangeMin,
        Long filterByAmountRangeMax,
        LocalDate  filterByDateRangeStart,
        LocalDate  filterByDateRangeEnd,
        int filterByMeanOfPayment
        ) {
            
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetAllEconomicExpenses", EconomicExpense.class);
        
        // Parámetros de entrada
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
        List<EconomicExpense> expenses = rawResults.stream()
            .filter(EconomicExpense.class::isInstance) 
            .map(EconomicExpense.class::cast)         
            .collect(Collectors.toList());


        // Mapear respuesta
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("economicExpenses", expenses);        
        return responseData;
    }

    @Transactional
    public int addEconomicExpense(Long pIdUser, LocalDate pRegistrationDate, String pVoucherNumber, 
                                String pDetail, Long pIdMeanOfPayment, Long pIdCategory, 
                                Float pAmount, Long pLoggedIdUser) {
        try {
            System.out.println("=== DEBUG ADD EXPENSE ===");
            System.out.println("pIdUser: " + pIdUser);
            System.out.println("pVoucherNumber: " + pVoucherNumber);
            System.out.println("pAmount: " + pAmount);
            
            int result = economicExpenseRepo.addEconomicExpense(pIdUser, pRegistrationDate, pVoucherNumber, 
                                                            pDetail, pIdMeanOfPayment, pIdCategory, 
                                                            pAmount, pLoggedIdUser);
            
            System.out.println("Result from repository: " + result);
            return result;
            
        } catch (Exception e) {
            System.out.println("=== ERROR IN ADD EXPENSE ===");
            System.out.println("Error type: " + e.getClass().getName());
            System.out.println("Error message: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Transactional
    public int updateEconomicExpense(Long pIdEconomicExpense, Long pIdUser, LocalDate pRegistrationDate, String pVoucherNumber, String pDetail, Long pIdMeanOfPayment, Long pIdCategory, Float pAmount, Long pIsDeleted, Long pLoggedIdUser){
        return economicExpenseRepo.updateEconomicExpense(pIdEconomicExpense, pIdUser, pRegistrationDate, pVoucherNumber, pDetail, pIdMeanOfPayment, pIdCategory, pAmount, pIsDeleted, pLoggedIdUser);
    }

    @Transactional
    public int deleteEconomicExpense(Long pIdEconomicExpense, Long pLoggedIdUser){
        return economicExpenseRepo.deleteEconomicExpense(pIdEconomicExpense, pLoggedIdUser);
    }

}