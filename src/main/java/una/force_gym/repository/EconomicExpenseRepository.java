package una.force_gym.repository;

import java.time.LocalDate;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.query.Procedure;
import org.springframework.data.repository.query.Param;

import una.force_gym.domain.EconomicExpense;

public interface EconomicExpenseRepository extends JpaRepository<EconomicExpense, Long>{
    
    @Procedure(procedureName = "prInsertEconomicExpense")
    int addEconomicExpense(@Param("pIdUser") Long pIdUser, @Param("pRegistrationDate") LocalDate pRegistrationDate, @Param("pVoucherNumber") String pVoucherNumber, @Param("pDetail") String pDetail, @Param("pIdMeanOfPayment") Long pIdMeanOfPayment, @Param("pIdCategory") Long pIdCategory, @Param("pAmount") Float pAmount, @Param("pLoggedIdUser") Long pLoggedIdUser);

    @Procedure(procedureName = "prUpdateEconomicExpense")
    int updateEconomicExpense(@Param("pIdEconomicExpense") Long pIdEconomicExpense, @Param("pIdUser") Long pIdUser, @Param("pRegistrationDate") LocalDate pRegistrationDate, @Param("pVoucherNumber") String pVoucherNumber, @Param("pDetail") String pDetail, @Param("pIdMeanOfPayment") Long pIdMeanOfPayment, @Param("pIdCategory") Long pIdCategory, @Param("pAmount") Float pAmount, @Param("pIsDeleted") Long pIsDeleted,  @Param("pLoggedIdUser") Long pLoggedIdUser);

    @Procedure(procedureName = "prDeleteEconomicExpense")
    int deleteEconomicExpense(@Param("pIdEconomicExpense") Long pIdEconomicExpense, @Param("pLoggedIdUser") Long pLoggedIdUser);
}