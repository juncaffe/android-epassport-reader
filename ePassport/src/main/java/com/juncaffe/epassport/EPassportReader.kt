package com.juncaffe.epassport

import android.nfc.Tag
import android.util.Log
import com.juncaffe.epassport.api.EPassportCallback
import com.juncaffe.epassport.model.State
import com.juncaffe.epassport.mrtd.*
import com.juncaffe.epassport.mrtd.lds.*
import com.juncaffe.epassport.mrtd.lds.icao.DG14File
import com.juncaffe.epassport.mrtd.lds.icao.DG2File
import com.juncaffe.epassport.mrtd.lds.iso19794.FaceInfo
import com.juncaffe.epassport.nfc.IsoDepCardService
import com.juncaffe.epassport.smartcard.CardService
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.X509Certificate

/**
 * 여권 칩 읽기
 * @param tag NFC 태그
 * @param fidList 여권 데이터 그룹 목록
 */
class EPassportReader(tag: Tag,
private val fidList: List<PassportService.EF> = listOf(PassportService.EF.DG1, PassportService.EF.DG2, PassportService.EF.DG14)
) {
    private val logTag = "ePassport"

    private val service: CardService = IsoDepCardService(tag)
    private val passportService = PassportService(
        service,
        PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
        PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
        PassportService.DEFAULT_MAX_BLOCKSIZE,
        true
    )

    private var callback: EPassportCallback? = null

    /** 여권 칩에 저장된 모든 데이터 그룹의 해시값과 이를 서명한 Document Signer 인증서 저장, Passive Authentication 에서 데이터 무결성 및 발급국 서명 검증에 사용 */
    private var sodFile: SODFile? = null

    /**
     * DG1File : 기계판독영역(MRZ) 정보 : 여권 번호, 국가 코드, 생년월일, 성별, 만료일 등
     * DG2File : 여권 사진 및 관련 메타데이터(FaceInfo)
     * DG3File : 지문 정보 (TA 인증 필요 - 안드로이드에서는 불가)
     * DG4File : 홍체 정보 (TA 인증 필요 - 안드로이드에서는 불가, 국내여권에는 없음)
     * DG14File : 칩 인증과 PACE 등 보안 프로토콜 관련 정보 저장 (ChipAuthenticationInfo, ChipAuthenticationPublicKeyInfo, PACEInfo)
     */
    private val dgFileMap = mutableMapOf<PassportService.EF, DataGroup?>()

    /**
     * 콜백 등록
     */
    fun setCallback(callback: EPassportCallback) {
        this.callback = callback
    }

    fun readPassport(mrzBytes: ByteArray) = readPassport(BACKey(mrzBytes))

    fun readPassport(passportNo: ByteArray, birthDate: ByteArray, expiryDate: ByteArray) =
        readPassport(BACKey(passportNo, birthDate, expiryDate))

    fun readPassport(bacKey: BACKey) {
        try {
            callback?.onState(State.CardAccess)
            if (doCardAccess(bacKey)) {
                callback?.onState(State.ChipAuthentication)
                if (chipAuthentication()) {
                    callback?.onState(State.PassiveAuthentication)
                    if (passiveAuthentication()) callback?.onComplete()
                }
            }
        } catch (e: Exception) {
            wipe()
            closeService()
            callback?.onError(e)
        } finally {
            bacKey.wipe()
        }
    }

    /**
     * 카드 접근 (PACE 없으면 BAC)
     * @param bacKey
     */
    private fun doCardAccess(bacKey: BACKeySpec): Boolean {
        passportService.open()
        val paceInfo = runCatching {
            val cardAccess = CardAccessFile(
                passportService.getInputStream(
                    PassportService.EF.CARD_ACCESS,
                    PassportService.DEFAULT_MAX_BLOCKSIZE
                )
            )
            cardAccess.securityInfos?.filterIsInstance<PACEInfo>()?.firstOrNull()
        }.getOrNull()

        return paceInfo?.let { doPACE(bacKey, it) } ?: doBAC(bacKey)
    }

    /**
     * PACE 인증
     * @param bacKey
     * @param paceInfo
     */
    private fun doPACE(bacKey: BACKeySpec, paceInfo: PACEInfo): Boolean = try {
        val spec = PACEInfo.toParameterSpec(paceInfo.parameterId)
        val result =
            passportService.doPACE(bacKey, paceInfo.objectIdentifier, spec, paceInfo.parameterId)
        (result.wrapper != null).also {
            if (it)
                passportService.sendSelectApplet(true)
        }
    } catch (e: Exception) {
        Log.i(logTag, "PACE failed: ${e.message}")
        throw e
    }

    /**
     * BAC 인증
     * @param bacKey
     * @return Boolean
     */
    private fun doBAC(bacKey: AccessKeySpec): Boolean {
        return try {
            passportService.sendSelectApplet(false)
            passportService.doBAC(bacKey).wrapper != null
        } catch (e: Exception) {
            Log.i(logTag, "BAC failed: ${e.message}")
            throw e
        }
    }

    /**
     * Chip Authentication
     * @param chipAuthenticationInfo
     * @param chipAuthenticationPublicKeyInfo
     * @return Boolean
     */
    private fun doEACCA(chipAuthenticationInfo: ChipAuthenticationInfo, chipAuthenticationPublicKeyInfo: ChipAuthenticationPublicKeyInfo): Boolean {
        val result = passportService.doEACCA(
            chipAuthenticationPublicKeyInfo.keyId,
            chipAuthenticationInfo.objectIdentifier,
            chipAuthenticationPublicKeyInfo.objectIdentifier,
            chipAuthenticationPublicKeyInfo.subjectPublicKey
        )
        return result.wrapper != null
    }

    /**
     * 칩 인증
     */
    fun chipAuthentication(): Boolean {
        val dg14 = DG14File(passportService.getInputStream(PassportService.EF.DG14, PassportService.DEFAULT_MAX_BLOCKSIZE))
        dgFileMap[PassportService.EF.DG14] = dg14

        val caInfo = dg14.securityInfos.filterIsInstance<ChipAuthenticationInfo>().firstOrNull()
        val pubKeyInfo = dg14.securityInfos.filterIsInstance<ChipAuthenticationPublicKeyInfo>().firstOrNull()

        return if (caInfo != null && pubKeyInfo != null)
            doEACCA(caInfo, pubKeyInfo)
        else
            throw SecurityException("Chip authentication failed")
    }

    /**
     * Passive Authentication (SOD 서명 + DG 해시 검증)
     * return Boolean
     */
    fun passiveAuthentication(): Boolean {
        sodFile = SODFile(passportService.getInputStream(PassportService.EF.SOD, PassportService.DEFAULT_MAX_BLOCKSIZE))
        val cert = sodFile?.getDocSigningCertificate()
        val verifySig = cert?.let {
            val sign = Signature.getInstance(it.sigAlgName)
            sign.initVerify(it)
            sign.update(sodFile!!.getEContent())
            sign.verify(sodFile!!.getEncryptedDigest())
        } ?: false

        val dataHashes = sodFile?.getDataGroupHashes().orEmpty()
        val digestAlg = sodFile?.getDigestAlgorithm() ?: return false

        val verifyHash = fidList.all { fid ->
            val dgFile = passportService.getDGFile(fid) { cur, acc, size ->
                callback?.onProgress(fid, cur, acc, size, passportService.getDataGroupSize(fidList))
            }
            dgFileMap[fid] = dgFile
            val dgHash = dgFile?.encoded?.let { MessageDigest.getInstance(digestAlg).digest(it) }
            dataHashes[fid.getSodKey()]?.contentEquals(dgHash) == true
        }

        if (!verifySig || !verifyHash) throw SecurityException("Passive authentication failed")
        return true
    }

    /**
     * 여권 얼굴 이미지
     */
    fun getFaceImage(): List<FaceInfo>? = (dgFileMap[PassportService.EF.DG2] as? DG2File)?.faceInfos

    /**
     * 여권 프로필 이미지
     */
    fun getProfileImage(): ByteArray? {
        return getFaceImage()?.firstOrNull()?.faceImageInfos
            ?.maxByOrNull { it!!.height * it.width }
            ?.getImageByteArray()
            ?.copyOf()
    }

    /**
     * 여권 인증서
     */
    fun getDocSigningCertificate(): X509Certificate? = sodFile?.getDocSigningCertificate()

    fun closeService() = passportService.close()

    /**
     * 메모리 클리어
     */
    fun wipe() = dgFileMap.values.forEach { it?.wipe() }
}