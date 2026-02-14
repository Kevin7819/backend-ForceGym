package una.force_gym.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import una.force_gym.domain.Client;
import una.force_gym.domain.Measurement;
import una.force_gym.domain.RoutineAssignment;
import una.force_gym.dto.ClientCredentialsDTO;
import una.force_gym.dto.ClientLoginDTO;
import una.force_gym.exception.AppException;
import una.force_gym.repository.ClientRepository;
import una.force_gym.repository.MeasurementRepository;
import una.force_gym.repository.RoutineAssignmentRepository;

@Service
public class ClientAuthService {

    @Autowired
    private ClientRepository clientRepository;

    @Autowired
    private RoutineAssignmentRepository routineAssignmentRepository;

    @Autowired
    private MeasurementRepository measurementRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Autenticación de clientes usando número de cédula y contraseña
     * Primero verifica si hay contraseña personalizada, si no, usa la provisional: inicial#cédula
     * Ejemplo provisional: G#703050481 donde G es la inicial del nombre
     */
    public ClientLoginDTO login(ClientCredentialsDTO credentials) {
        // Buscar todos los clientes activos
        List<Client> allClients = clientRepository.findAll();
        
        // Filtrar por número de identificación y que no esté eliminado
        Client client = allClients.stream()
            .filter(c -> c.getPerson() != null && 
                        c.getPerson().getIdentificationNumber() != null &&
                        c.getPerson().getIdentificationNumber().equals(credentials.getIdentificationNumber()) &&
                        Long.valueOf(0L).equals(c.getIsDeleted()))
            .findFirst()
            .orElseThrow(() -> new AppException("Cliente no encontrado", HttpStatus.NOT_FOUND));

        // Verificar contraseña
        boolean passwordMatches = false;
        
        // Si el cliente tiene contraseña personalizada, usarla
        if (client.getPassword() != null && !client.getPassword().isEmpty()) {
            passwordMatches = passwordEncoder.matches(
                credentials.getPassword(), 
                client.getPassword()
            );
        } else {
            // Si no tiene contraseña personalizada, usar la provisional (inicial#cédula)
            String provisionalPassword = generateClientPassword(
                client.getPerson().getName(), 
                client.getPerson().getIdentificationNumber()
            );
            passwordMatches = credentials.getPassword().equals(provisionalPassword);
        }
        
        if (passwordMatches) {
            ClientLoginDTO loginDTO = new ClientLoginDTO();
            loginDTO.setIdClient(client.getIdClient());
            loginDTO.setPerson(client.getPerson());
            return loginDTO;
        }
        
        throw new AppException("Credenciales inválidas", HttpStatus.BAD_REQUEST);
    }

    /**
     * Cambia la contraseña de un cliente
     * @param clientId ID del cliente
     * @param newPassword Nueva contraseña (se encriptará)
     */
    @Transactional
    public void changePassword(Long clientId, String newPassword) {
        Client client = clientRepository.findById(clientId)
                .orElseThrow(() -> new AppException("Cliente no encontrado", HttpStatus.NOT_FOUND));
        
        // Encriptar y guardar la nueva contraseña
        client.setPassword(passwordEncoder.encode(newPassword));
        clientRepository.save(client);
    }

    /**
     * Verifica si un cliente está usando contraseña provisional
     */
    public boolean hasProvisionalPassword(Long clientId) {
        Client client = clientRepository.findById(clientId)
                .orElseThrow(() -> new AppException("Cliente no encontrado", HttpStatus.NOT_FOUND));
        
        return client.getPassword() == null || client.getPassword().isEmpty();
    }

    /**
     * Genera la contraseña provisional para un cliente basado en su nombre y cédula
     * Formato: PrimeraLetraMayúscula#NúmeroCédula
     */
    public String generateClientPassword(String name, String identificationNumber) {
        if (name == null || name.isEmpty() || identificationNumber == null) {
            throw new IllegalArgumentException("Nombre y número de identificación son requeridos");
        }
        
        String inicial = name.substring(0, 1).toUpperCase();
        return inicial + "#" + identificationNumber;
    }

    /**
     * Obtiene las rutinas asignadas a un cliente
     */
    public List<RoutineAssignment> getClientRoutines(Long clientId) {
        System.out.println("=== DEBUG: Searching routines for clientId: " + clientId);
        List<RoutineAssignment> allAssignments = routineAssignmentRepository.findByClient_IdClient(clientId);
        System.out.println("=== DEBUG: Found " + allAssignments.size() + " total assignments");
        
        List<RoutineAssignment> filtered = allAssignments.stream()
            .filter(ra -> {
                boolean hasRoutine = ra.getRoutine() != null;
                boolean notDeleted = hasRoutine && Long.valueOf(0L).equals(ra.getRoutine().getIsDeleted());
                System.out.println("=== DEBUG: Assignment ID " + ra.getIdRoutineAssignment() + 
                                 ", hasRoutine=" + hasRoutine + 
                                 ", notDeleted=" + notDeleted);
                return hasRoutine && notDeleted;
            })
            .collect(Collectors.toList());
        
        System.out.println("=== DEBUG: Returning " + filtered.size() + " filtered routines");
        return filtered;
    }

    /**
     * Obtiene las medidas de un cliente
     */
    public List<Measurement> getClientMeasurements(Long clientId) {
        return measurementRepository.findAll().stream()
            .filter(m -> m.getClient() != null && 
                        m.getClient().getIdClient().equals(clientId) &&
                        Long.valueOf(0L).equals(m.getIsDeleted()))
            .collect(Collectors.toList());
    }
}
