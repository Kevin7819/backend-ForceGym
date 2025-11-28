package una.force_gym.repository;

import java.time.LocalDate;
import java.util.Date;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.query.Procedure;
import org.springframework.data.repository.query.Param;

import una.force_gym.domain.Client;

public interface ClientRepository extends JpaRepository<Client, Long> {

    @Procedure(procedureName = "prGetAllClient")
    List<Client> getAllClients();

    @Procedure(procedureName = "prInsertClient", outputParameterName = "result")
    int addClient(
        //Person
        @Param("pName") String pName, 
        @Param("pFirstLastName") String pFirstLastName, 
        @Param("pSecondLastName") String pSecondLastName, 
        @Param("pBirthday") LocalDate pBirthday, 
        @Param("pIdentificationNumber") String pIdentificationNumber, 
        @Param("pPhoneNumber") String pPhoneNumber, 
        @Param("pEmail") String pEmail, 
        @Param("pIdGender") Long pIdGender,

        @Param("pIdClientType") Long pIdClientType, 

        //HealthQuestionnaire
        @Param("pDiabetes") Boolean pDiabetes,
        @Param("pHypertension") Boolean pHypertension,
        @Param("pMuscleInjuries") Boolean pMuscleInjuries,
        @Param("pBoneJointIssues") Boolean pBoneJointIssues,
        @Param("pBalanceLoss") Boolean pBalanceLoss,
        @Param("pCardiovascularDisease") Boolean pCardiovascularDisease,
        @Param("pBreathingIssues") Boolean pBreathingIssues,

        @Param("pIdUser") Long pIdUser, 
        @Param("pRegistrationDate") Date registrationDate, 
        @Param("pExpirationMembershipDate") Date pExpirationMembershipDate, 
        @Param("pPhoneNumberContactEmergency") String pPhoneNumberContactEmergency, 
        @Param("pNameEmergencyContact") String pNameEmergencyContact, 
        @Param("pSignatureImage") String pSignatureImage, 
        @Param("pLoggedIdUser") Long pLoggedIdUser
    );

    @Procedure(procedureName = "prUpdateClient", outputParameterName = "result")
    int updateClient(
        @Param("pIdClient") Long pIdClient, 

        //Person
        @Param("pIdPerson") Long pIdPerson, 
        @Param("pName") String pName, 
        @Param("pFirstLastName") String pFirstLastName, 
        @Param("pSecondLastName") String pSecondLastName, 
        @Param("pBirthday") LocalDate pBirthday, 
        @Param("pIdentificationNumber") String pIdentificationNumber, 
        @Param("pPhoneNumber") String pPhoneNumber, 
        @Param("pEmail") String pEmail, 
        @Param("pIdGender") Long pIdGender, 

        @Param("pIdClientType") Long pIdClientType, 

        //HealthQuestionnaire
        @Param("pIdHealthQuestionnaire") Long pIdHealthQuestionnaire, 
        @Param("pDiabetes") Boolean pDiabetes,
        @Param("pHypertension") Boolean pHypertension,
        @Param("pMuscleInjuries") Boolean pMuscleInjuries,
        @Param("pBoneJointIssues") Boolean pBoneJointIssues,
        @Param("pBalanceLoss") Boolean pBalanceLoss,
        @Param("pCardiovascularDisease") Boolean pCardiovascularDisease,
        @Param("pBreathingIssues") Boolean pBreathingIssues,

        @Param("pIdUser") Long pIdUser, 
        @Param("pRegistrationDate") Date registrationDate, 
        @Param("pExpirationMembershipDate") Date pExpirationMembershipDate, 
        @Param("pPhoneNumberContactEmergency") String pPhoneNumberContactEmergency, 
        @Param("pNameEmergencyContact") String pNameEmergencyContact, 
        @Param("pSignatureImage") String pSignatureImage, 
        @Param("pIsDeleted") Long pIsDeleted,  
        @Param("pLoggedIdUser") Long pLoggedIdUser
    );

    @Procedure(procedureName = "prDeleteClient", outputParameterName = "result")
    int deleteClient(@Param("pIdClient") Long pIdClient, @Param("pLoggedIdUser") Long pLoggedIdUser);
}
