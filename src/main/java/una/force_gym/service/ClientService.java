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
import una.force_gym.domain.Client;
import una.force_gym.repository.ClientRepository;

@Service
public class ClientService {

    @Autowired
    private ClientRepository clientRepo;

    @PersistenceContext
    private EntityManager entityManager;

    public Map<String, Object> getClients(
            int page,
            int size, int searchType,
            String searchTerm,
            String orderBy,
            String directionOrderBy,
            String filterByStatus,
            //HealthQuestionnaire 
            Boolean filterByDiabetes,
            Boolean filterByHypertension,
            Boolean filterByMuscleInjuries,
            Boolean filterByBoneJointIssues,
            Boolean filterByBalanceLoss,
            Boolean filterByCardiovascularDisease,
            Boolean filterByBreathingIssues,
            //Person
            LocalDate filterByDateBirthStart,
            LocalDate filterByDateBirthEnd,
            int filterByClientType
    ) {

        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetClient", Client.class);

        // Parámetros de entrada
        query.registerStoredProcedureParameter("p_page", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_limit", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchType", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchTerm", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_orderBy", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_directionOrderBy", String.class, ParameterMode.IN);

        query.registerStoredProcedureParameter("p_filterByStatus", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByDiabetes", Boolean.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByHypertension", Boolean.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByMuscleInjuries", Boolean.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByBoneJointIssues", Boolean.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByBalanceLoss", Boolean.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByCardiovascularDisease", Boolean.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByBreathingIssues", Boolean.class, ParameterMode.IN);

        query.registerStoredProcedureParameter("p_filterByDateBirthStart", LocalDate.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByDateBirthEnd", LocalDate.class, ParameterMode.IN);

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

        query.setParameter("p_filterByDiabetes", filterByDiabetes);
        query.setParameter("p_filterByHypertension", filterByHypertension);
        query.setParameter("p_filterByMuscleInjuries", filterByMuscleInjuries);
        query.setParameter("p_filterByBoneJointIssues", filterByBoneJointIssues);
        query.setParameter("p_filterByBalanceLoss", filterByBalanceLoss);
        query.setParameter("p_filterByCardiovascularDisease", filterByCardiovascularDisease);
        query.setParameter("p_filterByBreathingIssues", filterByBreathingIssues);

        query.setParameter("p_filterByDateBirthStart", filterByDateBirthStart);
        query.setParameter("p_filterByDateBirthEnd", filterByDateBirthEnd);

        query.setParameter("p_filterByClientType", filterByClientType);

        // Ejecutar procedimiento
        query.execute();

        // Obtener los resultados
        List<?> rawResults = query.getResultList();
        List<Client> clients = rawResults.stream()
                .filter(Client.class::isInstance)
                .map(Client.class::cast)
                .collect(Collectors.toList());

        Integer totalRecords = (Integer) query.getOutputParameterValue("p_totalRecords");

        // Mapear respuesta
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("clients", clients);
        responseData.put("totalRecords", totalRecords);

        return responseData;
    }

    @Transactional
    public List<Client> getAllClients() {
        return clientRepo.getAllClients();
    }

    public Map<String, Object> getClientsByFilter(Integer filterType) {
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetClientsByFilter");

        // Registrar parámetros
        query.registerStoredProcedureParameter("pFilterType", Integer.class, ParameterMode.IN);

        // Asignar valores a los parámetros
        query.setParameter("pFilterType", filterType);

        // Ejecutar procedimiento
        query.execute();

        // Obtener los resultados
        List<Object[]> rawResults = query.getResultList();

        // Convertir resultados a una lista de mapas
        List<Map<String, Object>> clients = rawResults.stream().map(record -> {
            Map<String, Object> map = new HashMap<>();
            map.put("idClient", record[0]);
            map.put("name", record[1]);
            map.put("firstLastName", record[2]);
            map.put("secondLastName", record[3]);
            map.put("email", record[4]);
            map.put("phoneNumber", record[5]);
            map.put("additionalInfo", record.length > 6 ? record[6] : null); // Puede ser fecha de registro, cumpleaños o null
            return map;
        }).collect(Collectors.toList());

        // Armar respuesta
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("clients", clients);
        responseData.put("totalRecords", clients.size());

        return responseData;
    }

    @Transactional
    public int addClient(
            String pName,
            String pFirstLastName,
            String pSecondLastName,
            LocalDate pBirthday,
            String pIdentificationNumber,
            String pPhoneNumber,
            String pEmail,
            Long pIdGender,
            Long pIdClientType,
            Boolean pDiabetes,
            Boolean pHypertension,
            Boolean pMuscleInjuries,
            Boolean pBoneJointIssues,
            Boolean pBalanceLoss,
            Boolean pCardiovascularDisease,
            Boolean pBreathingIssues,
            Long pIdUser,
            Date pRegistrationDate,
            Date pExpirationMembershipDate,
            String pPhoneNumberContactEmergency,
            String pNameEmergencyContact,
            String pSignatureImage,
            Long pLoggedIdUser) {
        return clientRepo.addClient(
                pName,
                pFirstLastName,
                pSecondLastName,
                pBirthday,
                pIdentificationNumber,
                pPhoneNumber,
                pEmail,
                pIdGender,
                pIdClientType,
                pDiabetes,
                pHypertension,
                pMuscleInjuries,
                pBoneJointIssues,
                pBalanceLoss,
                pCardiovascularDisease,
                pBreathingIssues,
                pIdUser,
                pRegistrationDate,
                pExpirationMembershipDate,
                pPhoneNumberContactEmergency,
                pNameEmergencyContact,
                pSignatureImage,
                pLoggedIdUser);
    }

    @Transactional
    public int updateClient(Long pIdClient,
            Long pIdPerson,
            String pName,
            String pFirstLastName,
            String pSecondLastName,
            LocalDate pBirthday,
            String pIdentificationNumber,
            String pPhoneNumber,
            String pEmail,
            Long pIdGender,
            Long pIdClientType,
            Long pIdHealthQuestionnaire,
            Boolean pDiabetes,
            Boolean pHypertension,
            Boolean pMuscleInjuries,
            Boolean pBoneJointIssues,
            Boolean pBalanceLoss,
            Boolean pCardiovascularDisease,
            Boolean pBreathingIssues,
            Long pIdUser,
            Date pRegistrationDate,
            Date pExpirationMembershipDate,
            String pPhoneNumberContactEmergency,
            String pNameEmergencyContact,
            String pSignatureImage,
            Long pIsDeleted,
            Long pLoggedIdUser) {
        return clientRepo.updateClient(pIdClient,
                pIdPerson,
                pName,
                pFirstLastName,
                pSecondLastName,
                pBirthday,
                pIdentificationNumber,
                pPhoneNumber,
                pEmail,
                pIdGender,
                pIdClientType,
                pIdHealthQuestionnaire,
                pDiabetes,
                pHypertension,
                pMuscleInjuries,
                pBoneJointIssues,
                pBalanceLoss,
                pCardiovascularDisease,
                pBreathingIssues,
                pIdUser,
                pRegistrationDate,
                pExpirationMembershipDate,
                pPhoneNumberContactEmergency,
                pNameEmergencyContact,
                pSignatureImage,
                pIsDeleted,
                pLoggedIdUser);
    }

    @Transactional
    public int deleteClient(Long pIdClient, Long pLoggedIdUser) {
        return clientRepo.deleteClient(pIdClient, pLoggedIdUser);
    }
}
