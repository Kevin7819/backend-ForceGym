package una.force_gym.repository;

import una.force_gym.domain.Measurement;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.query.Procedure;
import org.springframework.data.repository.query.Param;

import java.util.Date;

public interface MeasurementRepository extends JpaRepository<Measurement, Long> {
   
    @Procedure(procedureName = "prInsertMeasurement", outputParameterName = "result")
    int addMeasurement(
        @Param("pIdClient") Long pIdClient,
        @Param("pMeasurementDate") Date pMeasurementDate,
        @Param("pWeight") Float pWeight,
        @Param("pHeight") Float pHeight,
        @Param("pBmi") Float pBmi,
        @Param("pMuscleMass") Float pMuscleMass,
        @Param("pBodyFatPercentage") Float pBodyFatPercentage,
        @Param("pVisceralFatPercentage") Float pVisceralFatPercentage,
        @Param("pChestSize") Float pChestSize,
        @Param("pBackSize") Float pBackSize,
        @Param("pHipSize") Float pHipSize,
        @Param("pWaistSize") Float pWaistSize,
        @Param("pLeftLegSize") Float pLeftLegSize,
        @Param("pRightLegSize") Float pRightLegSize,
        @Param("pLeftCalfSize") Float pLeftCalfSize,
        @Param("pRightCalfSize") Float pRightCalfSize,
        @Param("pLeftForeArmSize") Float pLeftForeArmSize,
        @Param("pRightForeArmSize") Float pRightForeArmSize,
        @Param("pLeftArmSize") Float pLeftArmSize,
        @Param("pRightArmSize") Float pRightArmSize,
        @Param("pParamLoggedIdUser") Long pParamLoggedIdUser
    );

    @Procedure(procedureName = "prUpdateMeasurement", outputParameterName = "result")
    int updateMeasurement(
        @Param("pIdMeasurement") Long pIdMeasurement,
        @Param("pIdClient") Long pIdClient,
        @Param("pMeasurementDate") Date pMeasurementDate,
        @Param("pWeight") Float pWeight,
        @Param("pHeight") Float pHeight,
        @Param("pBmi") Float pBmi,
        @Param("pMuscleMass") Float pMuscleMass,
        @Param("pBodyFatPercentage") Float pBodyFatPercentage,
        @Param("pVisceralFatPercentage") Float pVisceralFatPercentage,
        @Param("pChestSize") Float pChestSize,
        @Param("pBackSize") Float pBackSize,
        @Param("pHipSize") Float pHipSize,
        @Param("pWaistSize") Float pWaistSize,
        @Param("pLeftLegSize") Float pLeftLegSize,
        @Param("pRightLegSize") Float pRightLegSize,
        @Param("pLeftCalfSize") Float pLeftCalfSize,
        @Param("pRightCalfSize") Float pRightCalfSize,
        @Param("pLeftForeArmSize") Float pLeftForeArmSize,
        @Param("pRightForeArmSize") Float pRightForeArmSize,
        @Param("pLeftArmSize") Float pLeftArmSize,
        @Param("pRightArmSize") Float pRightArmSize,
        @Param("pIsDeleted") Long pIsDeleted,
        @Param("pParamLoggedIdUser") Long pParamLoggedIdUser
    );

    @Procedure(procedureName = "prDeleteMeasurement", outputParameterName = "result")
    int deleteMeasurement(@Param("pIdMeasurement") Long pIdMeasurement, @Param("pLoggedIdUser") Long pLoggedIdUser);
}