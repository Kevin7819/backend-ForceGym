package una.force_gym.service;

import una.force_gym.domain.ActivityType;
import una.force_gym.domain.ClientType;
import una.force_gym.domain.Fee;
import una.force_gym.dto.ActivityTypeWithFeesDTO;
import una.force_gym.dto.FeeDTO;
import una.force_gym.repository.ActivityTypeRepository;
import una.force_gym.repository.ClientTypeRepository;
import una.force_gym.repository.FeeRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class ActivityTypeService {

    @Autowired
    private ActivityTypeRepository activityTypeRepository;

    @Autowired
    private FeeRepository feeRepository;

    @Autowired
    private ClientTypeRepository clientTypeRepository;

    @Transactional
    public ActivityType saveWithFees(ActivityTypeWithFeesDTO dto) {
        final ActivityType activityType = new ActivityType();
        activityType.setName(dto.getName());
        activityType.setDurationDays(dto.getDurationDays() != null ? dto.getDurationDays() : 0);
        activityType.setIsDeleted(0L);
        ActivityType savedActivityType = activityTypeRepository.save(activityType);
        
        List<Fee> fees = dto.getFees().stream()
            .flatMap(feeDto -> feeDto.getIdClientType().stream()
                .map(idClientType -> {
                    Fee fee = new Fee();
                    fee.setActivityType(savedActivityType);
                    
                    ClientType clientType = clientTypeRepository.findById(idClientType)
                        .orElseThrow(() -> new RuntimeException(
                            "ClientType no encontrado con ID: " + idClientType));
                    
                    fee.setClientType(clientType);
                    fee.setAmount(feeDto.getAmount());
                    return fee;
                }))
            .collect(Collectors.toList());
            
        feeRepository.saveAll(fees);
        
        return savedActivityType;
    }

    @Transactional
    public ActivityType updateWithFees(ActivityTypeWithFeesDTO dto) {
        final ActivityType activityType = activityTypeRepository.findById(dto.getIdActivityType())
            .orElseThrow(() -> new RuntimeException("ActivityType no encontrado"));
        activityType.setName(dto.getName());
        activityType.setDurationDays(dto.getDurationDays() != null ? dto.getDurationDays() : 0);
        ActivityType updatedActivityType = activityTypeRepository.save(activityType);
        
        // Eliminar tarifas existentes
        feeRepository.deleteByActivityTypeId(updatedActivityType.getIdActivityType());
        
        // Guardar las nuevas tarifas
        List<Fee> fees = dto.getFees().stream()
            .flatMap(feeDto -> feeDto.getIdClientType().stream()
                .map(idClientType -> {
                    Fee fee = new Fee();
                    fee.setActivityType(updatedActivityType);
                    
                    ClientType clientType = clientTypeRepository.findById(idClientType)
                        .orElseThrow(() -> new RuntimeException(
                            "ClientType no encontrado con ID: " + idClientType));
                    
                    fee.setClientType(clientType);
                    fee.setAmount(feeDto.getAmount());
                    return fee;
                }))
            .collect(Collectors.toList());
            
        feeRepository.saveAll(fees);
        
        return updatedActivityType;
    }

    @Transactional
    public List<ActivityType> getActivityTypes(){
        return activityTypeRepository.findActiveActivityTypes();
    }

    @Transactional(readOnly = true)
    public List<ActivityTypeWithFeesDTO> getActivityTypesWithFees() {
        List<ActivityType> activityTypes = activityTypeRepository.findActiveActivityTypes();
        
        return activityTypes.stream().map(activity -> {
            ActivityTypeWithFeesDTO dto = new ActivityTypeWithFeesDTO();
            dto.setIdActivityType(activity.getIdActivityType());
            dto.setName(activity.getName());
            dto.setDurationDays(activity.getDurationDays());
            dto.setIsDeleted(activity.getIsDeleted());
            
            List<Fee> fees = feeRepository.findByActivityType_IdActivityType(activity.getIdActivityType());
            
            Map<Double, List<Long>> feesGrouped = fees.stream()
                .collect(Collectors.groupingBy(
                    Fee::getAmount,
                    Collectors.mapping(
                        fee -> fee.getClientType().getIdClientType(),
                        Collectors.toList()
                    )
                ));
            
            List<FeeDTO> feeDtos = feesGrouped.entrySet().stream()
                .map(entry -> {
                    FeeDTO feeDto = new FeeDTO();
                    feeDto.setIdClientType(entry.getValue());
                    feeDto.setAmount(entry.getKey());
                    return feeDto;
                })
                .collect(Collectors.toList());
                
            dto.setFees(feeDtos);
            return dto;
        }).collect(Collectors.toList());
    }

    @Transactional
    public void deleteWithFees(Long id) {
        ActivityType activityType = activityTypeRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("ActivityType no encontrado con ID: " + id));
        
        // Borrado lógico
        activityTypeRepository.softDelete(id);
        
        // Opcional: borrado lógico de las tarifas asociadas
        // feeRepository.softDeleteByActivityTypeId(id);
    }
}