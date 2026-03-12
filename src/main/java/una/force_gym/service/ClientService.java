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

    @Transactional
    public void deleteClientPermanently(Long pIdClient, Long pLoggedIdUser) {
        Client client = clientRepo.findById(pIdClient)
            .orElseThrow(() -> new RuntimeException("Cliente no encontrado"));
        
        // Obtener los IDs antes de eliminar
        Long idPerson = client.getPerson() != null ? client.getPerson().getIdPerson() : null;
        Long idHealthQuestionnaire = client.getHealthQuestionnaire() != null ? 
            client.getHealthQuestionnaire().getIdHealthQuestionnaire() : null;
        
        // Verificar si hay ingresos económicos asociados
        Long incomeCount = (Long) entityManager.createNativeQuery(
            "SELECT COUNT(*) FROM tbEconomicIncome WHERE idClient = :idClient AND isDeleted = 0")
            .setParameter("idClient", pIdClient)
            .getSingleResult();
        
        if (incomeCount > 0) {
            throw new RuntimeException("No se puede eliminar permanentemente este cliente porque tiene " + 
                incomeCount + " ingreso(s) económico(s) asociado(s). " +
                "Los registros financieros deben preservarse. " +
                "Use la opción de 'Eliminar' (marcar como inactivo) en su lugar.");
        }
        
        // Desactivar temporalmente las verificaciones de llaves foráneas
        entityManager.createNativeQuery("SET FOREIGN_KEY_CHECKS = 0").executeUpdate();
        
        try {
            // 1. Eliminar registros relacionados usando SQL nativo
            // Notas de ejercicios del portal de cliente
            entityManager.createNativeQuery("DELETE FROM tbClientExerciseNote WHERE idClient = :idClient")
                .setParameter("idClient", pIdClient)
                .executeUpdate();
            
            // Ejercicios de rutina de las asignaciones del cliente
            entityManager.createNativeQuery("DELETE FROM tbRoutineExercise WHERE idRoutine IN " +
                "(SELECT idRoutine FROM tbRoutineAssignment WHERE idClient = :idClient)")
                .setParameter("idClient", pIdClient)
                .executeUpdate();
            
            // Asignaciones de rutinas
            entityManager.createNativeQuery("DELETE FROM tbRoutineAssignment WHERE idClient = :idClient")
                .setParameter("idClient", pIdClient)
                .executeUpdate();
            
            // Mediciones
            entityManager.createNativeQuery("DELETE FROM tbMeasurement WHERE idClient = :idClient")
                .setParameter("idClient", pIdClient)
                .executeUpdate();
            
            // Notificaciones
            entityManager.createNativeQuery("DELETE FROM tbNotification WHERE idClient = :idClient")
                .setParameter("idClient", pIdClient)
                .executeUpdate();
            
            // Tokens de reseteo de contraseña
            entityManager.createNativeQuery("DELETE FROM tbClientPasswordRecovery WHERE idClient = :idClient")
                .setParameter("idClient", pIdClient)
                .executeUpdate();
            
            // 2. Eliminar el cliente
            entityManager.createNativeQuery("DELETE FROM tbClient WHERE idClient = :idClient")
                .setParameter("idClient", pIdClient)
                .executeUpdate();
            
            // 3. Eliminar cuestionario de salud si existe
            if (idHealthQuestionnaire != null) {
                entityManager.createNativeQuery("DELETE FROM tbHealthQuestionnaire WHERE idHealthQuestionnaire = :id")
                    .setParameter("id", idHealthQuestionnaire)
                    .executeUpdate();
            }
            
            // 4. Eliminar persona si existe (verificar que no esté siendo usada por otros registros)
            if (idPerson != null) {
                // Verificar si la persona está siendo usada por otro cliente o usuario
                Long countClient = (Long) entityManager.createNativeQuery(
                    "SELECT COUNT(*) FROM tbClient WHERE idPerson = :idPerson")
                    .setParameter("idPerson", idPerson)
                    .getSingleResult();
                
                Long countUser = (Long) entityManager.createNativeQuery(
                    "SELECT COUNT(*) FROM tbUser WHERE idPerson = :idPerson")
                    .setParameter("idPerson", idPerson)
                    .getSingleResult();
                
                // Solo eliminar si no está siendo usada
                if (countClient == 0 && countUser == 0) {
                    entityManager.createNativeQuery("DELETE FROM tbPerson WHERE idPerson = :idPerson")
                        .setParameter("idPerson", idPerson)
                        .executeUpdate();
                }
            }
            
            entityManager.flush();
        } finally {
            // Reactivar las verificaciones de llaves foráneas
            entityManager.createNativeQuery("SET FOREIGN_KEY_CHECKS = 1").executeUpdate();
        }
    }

    @Transactional(readOnly = true)
    public List<Client> getClientsByMembershipExpiration(int year, int month) {
        LocalDate startLocalDate = LocalDate.of(year, month, 1);
        LocalDate endLocalDate = startLocalDate.withDayOfMonth(startLocalDate.lengthOfMonth());
        
        // Convertir LocalDate a Date
        Date startDate = java.sql.Date.valueOf(startLocalDate);
        Date endDate = java.sql.Date.valueOf(endLocalDate);
        
        return clientRepo.findByExpirationMembershipDateBetweenAndIsDeleted(startDate, endDate, 0L);
    }
}
