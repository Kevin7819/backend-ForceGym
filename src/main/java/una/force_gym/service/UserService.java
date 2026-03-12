package una.force_gym.service;

import java.nio.CharBuffer;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.ParameterMode;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.StoredProcedureQuery;
import una.force_gym.domain.User;
import una.force_gym.dto.CredentialsDTO;
import una.force_gym.dto.LoginDTO;
import una.force_gym.dto.UserDTO;
import una.force_gym.exception.AppException;
import una.force_gym.mapper.UserMapper;
import una.force_gym.repository.UserRepository;

@Service
public class UserService {
    
    @Autowired 
    private UserRepository userRepo;

    @Autowired 
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserMapper userMapper;
    
    @PersistenceContext
    private EntityManager entityManager;

    public Map<String, Object> getUsers(
        int page, 
        int size, int searchType, 
        String searchTerm, 
        String orderBy, 
        String directionOrderBy, 
        String filterByStatus, 
        String filterByRole
    ) {
            
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetUser", UserDTO.class);
        
        // Parámetros de entrada
        query.registerStoredProcedureParameter("p_page", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_limit", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchType", Integer.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_searchTerm", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_orderBy", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_directionOrderBy", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByStatus", String.class, ParameterMode.IN);
        query.registerStoredProcedureParameter("p_filterByRole", String.class, ParameterMode.IN);

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
        query.setParameter("p_filterByRole", filterByRole);

        // Ejecutar procedimiento
        query.execute();

        // Obtener los resultados
        List<?> rawResults = query.getResultList();
        List<UserDTO> users = rawResults.stream()
            .filter(UserDTO.class::isInstance) 
            .map(UserDTO.class::cast)         
            .collect(Collectors.toList());
        Integer totalRecords = (Integer) query.getOutputParameterValue("p_totalRecords");

        // Mapear respuesta
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("users", users);
        responseData.put("totalRecords", totalRecords);
        
        return responseData;
    }

        @Transactional
    public Map<String, Object> getUserById(Long idUser) {
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("prGetUserById", UserDTO.class);
        
        // Parámetros de entrada
        query.registerStoredProcedureParameter("p_idUser", Long.class, ParameterMode.IN);
        
        // Parámetro de salida (para consistencia con prGetUser)
        query.registerStoredProcedureParameter("p_totalRecords", Integer.class, ParameterMode.OUT);

        // Setear valores
        query.setParameter("p_idUser", idUser);

        // Ejecutar procedimiento
        query.execute();

        // Obtener los resultados
        List<?> rawResults = query.getResultList();
        List<UserDTO> users = rawResults.stream()
            .filter(UserDTO.class::isInstance) 
            .map(UserDTO.class::cast)         
            .collect(Collectors.toList());
        
        // Obtener el parámetro de salida (siempre será 1 cuando se encuentra el usuario)
        Integer totalRecords = (Integer) query.getOutputParameterValue("p_totalRecords");

        // Mapear respuesta
        Map<String, Object> responseData = new HashMap<>();
        
        if(!users.isEmpty()) {
            responseData.put("user", users.get(0)); // Devolvemos el primer y único usuario
            responseData.put("totalRecords", totalRecords != null ? totalRecords : 1);
        } else {
            responseData.put("user", null);
            responseData.put("totalRecords", 0);
        }
        
        return responseData;
    }
    
    @Transactional
    public int addUser(Long pIdRole, String pName, String pFirstLastName, String pSecondLastName, LocalDate pBirthday, String pIdentificationNumber, String pPhoneNumber, String pEmail, Long pIdGender, String pUsername, String pPassword, Long pLoggedIdUser){
        String encodedPassword = (pPassword != null) ? passwordEncoder.encode(pPassword) : null;
        return userRepo.addUser(pIdRole, pName, pFirstLastName, pSecondLastName, pBirthday, pIdentificationNumber, pPhoneNumber, pEmail, pIdGender, pUsername, encodedPassword, pLoggedIdUser);
    }

    @Transactional
    public int updateUser(Long pIdUser, Long pIdRole, Long pIdPerson, String pName, String pFirstLastName, String pSecondLastName, LocalDate pBirthday, String pIdentificationNumber, String pPhoneNumber, String pEmail, Long pIdGender, String pUsername, String pPassword, Long pIsDeleted, Long pLoggedIdUser){
        String encodedPassword = (pPassword != null) ? passwordEncoder.encode(pPassword) : null;
        return userRepo.updateUser(pIdUser, pIdRole, pIdPerson, pName, pFirstLastName, pSecondLastName, pBirthday, pIdentificationNumber, pPhoneNumber, pEmail, pIdGender, pUsername, encodedPassword, pIsDeleted, pLoggedIdUser);
    }

    @Transactional
    public int deleteUser(Long pIdUser, Long pLoggedIdUser){
        return userRepo.deleteUser(pIdUser, pLoggedIdUser);
    }

    @Transactional
    public void deleteUserPermanently(Long pIdUser, Long pLoggedIdUser) {
        User user = userRepo.findById(pIdUser)
            .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
        
        // Obtener el ID de la persona antes de eliminar
        Long idPerson = user.getPerson() != null ? user.getPerson().getIdPerson() : null;
        
        // Verificar si hay clientes asociados a este usuario (el usuario creó clientes)
        Long clientCount = (Long) entityManager.createNativeQuery(
            "SELECT COUNT(*) FROM tbClient WHERE idUser = :idUser")
            .setParameter("idUser", pIdUser)
            .getSingleResult();
        
        if (clientCount > 0) {
            throw new RuntimeException("No se puede eliminar el usuario porque tiene clientes asociados. " +
                "Primero debe reasignar o eliminar los clientes asociados.");
        }
        
        // 1. Eliminar registros relacionados
        // Gastos económicos
        entityManager.createNativeQuery("DELETE FROM tbEconomicExpense WHERE idUser = :idUser")
            .setParameter("idUser", pIdUser)
            .executeUpdate();
        
        // Plantillas de notificaciones
        entityManager.createNativeQuery("DELETE FROM tbNotificationTemplate WHERE idUser = :idUser")
            .setParameter("idUser", pIdUser)
            .executeUpdate();
        
        // Verificar si hay rutinas asociadas
        Long routineCount = (Long) entityManager.createNativeQuery(
            "SELECT COUNT(*) FROM tbRoutine WHERE idUser = :idUser")
            .setParameter("idUser", pIdUser)
            .getSingleResult();
        
        if (routineCount > 0) {
            throw new RuntimeException("No se puede eliminar el usuario porque tiene rutinas creadas. " +
                "Primero debe reasignar o eliminar las rutinas asociadas.");
        }
        
        // 2. Eliminar el usuario
        entityManager.createNativeQuery("DELETE FROM tbUser WHERE idUser = :idUser")
            .setParameter("idUser", pIdUser)
            .executeUpdate();
        
        // 3. Eliminar persona si existe (verificar que no esté siendo usada por otros registros)
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
    }

    @Transactional
    public LoginDTO login(CredentialsDTO credentialsDTO) {
        User user = userRepo.findByUsernameAndIsDeleted(credentialsDTO.getUsername(), Long.valueOf(0))
                .orElseThrow(() -> new AppException("Usuario inválido", HttpStatus.NOT_FOUND));

        if (passwordEncoder.matches(CharBuffer.wrap(credentialsDTO.getPassword()), user.getPassword())) {
            return userMapper.toLoginDTO(user);
        }
        throw new AppException("Credenciales inválidas", HttpStatus.BAD_REQUEST);
    }

    @Transactional
    public UserDTO findByUsername(String username) {
        User user = userRepo.findByUsernameAndIsDeleted(username, Long.valueOf(0))
                .orElseThrow(() -> new AppException("Usuario inválido", HttpStatus.NOT_FOUND));
        return userMapper.toUserDTO(user);
    }

    @Transactional
    public User findByEmail(String email) {
        User user = userRepo.findByPersonEmailAndIsDeleted(email, Long.valueOf(0))
                .orElseThrow(() -> new AppException("Usuario inválido", HttpStatus.NOT_FOUND));
        return user;
    }

}
