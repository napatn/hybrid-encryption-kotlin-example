package nty.example.hybridencryptionkotlinexample

import com.fasterxml.jackson.databind.PropertyNamingStrategy
import com.fasterxml.jackson.databind.annotation.JsonNaming
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.*
import java.nio.charset.StandardCharsets
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.security.Key
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyGenerator
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.Security


@RestController
@RequestMapping("/hybrid")
class HybridController(val cryptoHelper: HybridCryptoHelper) {

    @PostMapping("/encrypt")
    fun encrypt(@RequestBody request: EncryptRequest): EncryptResponse {
        val cipherText = cryptoHelper.encryptAESGCMToBase64(request.plainText!!, request.plainKey!!)
        val encryptedKey = cryptoHelper.encryptBase64RSA(request.plainKey!!, cryptoHelper.convertStringToBase64PublicKey(Keys.RSA_PUBLIC_1024.value)!!)

        return EncryptResponse(cipherText = cipherText,
                cipherKey = encryptedKey)
    }

    @PostMapping("/decrypt")
    fun decrypt(@RequestBody request: DecryptRequest): DecryptResponse {
        val plainKey = cryptoHelper.decryptBase64RSA(request.cipherKey!!, cryptoHelper.convertStringToBase64PrivateKey(Keys.RSA_PRIVATE_1024.value)!!)
        val plainText = cryptoHelper.decryptAESGCMFromBase64(request.cipherText!!, plainKey!!)

        return DecryptResponse(plainText = plainText,
                plainKey = plainKey)
    }

    @GetMapping("/key")
    fun generateAESKey(): GenerateKeyResponse {
        val plainKey = cryptoHelper.generateAESKey()
        val encryptedKey = cryptoHelper.encryptBase64RSA(plainKey, cryptoHelper.convertStringToBase64PublicKey(Keys.RSA_PUBLIC_1024.value)!!)

        return GenerateKeyResponse(plainKey = plainKey,
                rsaEncryptedKey = encryptedKey)
    }

}

@Service
class HybridCryptoHelper {

    private val AESGCM_INSTANCE = "AES/GCM/NoPadding"
    private val RSA_INSTANCE = "RSA/None/PKCS1Padding"
    private val GCM_IV_LENGTH = 12
    private val GCM_TAG_LENGTH = 16
    private val AES_KEY_LENGTH_IN_BYTE = 32

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun getAESSecretKeyFromString(encodedKey: String): SecretKey {
        val decodedKey = Base64.getDecoder().decode(encodedKey)
        return SecretKeySpec(decodedKey, 0, decodedKey.size, "AES")
    }

    //    https://generate.plus/en/base64
    fun generateAESKey(): String {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(AES_KEY_LENGTH_IN_BYTE * 8) // for example
        val secretKey = keyGen.generateKey()

        return  Base64.getEncoder().encodeToString(secretKey.encoded)
    }

    fun encryptAESGCMToBase64(plaintext: String, key: String): String? {
        try {
            val cipher = Cipher.getInstance(AESGCM_INSTANCE)
            val keySpec = getAESSecretKeyFromString(key)

            val gcmParameterSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, ByteArray(GCM_IV_LENGTH))

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec)
            val cipherText = cipher.doFinal(plaintext.toByteArray())

            return Base64.getEncoder().encodeToString(cipherText)
        } catch (e: Exception) {
            return null
        }

    }

    fun decryptAESGCMFromBase64(cipherText: String, key: String): String? {
        try {
            val cipher = Cipher.getInstance(AESGCM_INSTANCE)
            val keySpec = getAESSecretKeyFromString(key)

            val gcmParameterSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, ByteArray(GCM_IV_LENGTH))

            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec)
            val decryptedText = cipher.doFinal(Base64.getDecoder().decode(cipherText))

            return String(decryptedText, StandardCharsets.UTF_8)
        } catch (e: Exception) {
            return null
        }
    }

    fun encryptBase64RSA(plainText: String, key: Key): String? {
        try {
            val input = plainText.toByteArray(charset("UTF-8"))
            val cipher = Cipher.getInstance(RSA_INSTANCE, "BC")

            cipher.init(Cipher.ENCRYPT_MODE, key)
            val cipherText = cipher.doFinal(input)
            return Base64.getEncoder().encodeToString(cipherText)
        } catch (e: Exception) {
            return null
        }
    }

    fun decryptBase64RSA(encryptedTxt: String, key: Key): String? {
        try {
            val cipher = Cipher.getInstance(RSA_INSTANCE, "BC")
            cipher.init(Cipher.DECRYPT_MODE, key)
            val plainText = cipher.doFinal(decodedBase64EncryptedText(encryptedTxt))
            return String(plainText, charset("UTF-8"))
        } catch (e: Exception) {
            return null
        }

    }


    fun convertStringToBase64PublicKey(publicKey: String): PublicKey? {
        try {
            val keyFactory = KeyFactory.getInstance("RSA", "BC")
            val publicKeySpec = X509EncodedKeySpec(encodedBase64KeySpec(publicKey))
            return keyFactory.generatePublic(publicKeySpec)
        } catch (e: Exception) {
            return null
        }

    }


    fun convertStringToBase64PrivateKey(privateKey: String): PrivateKey? {
        try {
            val keyFactory = KeyFactory.getInstance("RSA", "BC")
            val privateKeySpec = PKCS8EncodedKeySpec(decodedBase64KeySpec(privateKey))
            return keyFactory.generatePrivate(privateKeySpec)
        } catch (e: Exception) {
            return null
        }

    }

    private fun encodedBase64KeySpec(publicKey: String): ByteArray {
        return Base64.getDecoder().decode(publicKey)
    }

    private fun decodedBase64KeySpec(privateKey: String): ByteArray {
        return Base64.getDecoder().decode(privateKey)
    }

    private fun decodedBase64EncryptedText(encryptedTxt: String): ByteArray {
        return Base64.getDecoder().decode(encryptedTxt)
    }
}

enum class Keys(val value: String) {
//    generated using this online tool
//    https://www.devglan.com/online-tools/rsa-encryption-decryption
    RSA_PUBLIC_1024("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCSAsbTSVBfsbWfki1iop2LGCI+70UWaXoWhzcVoazg/jblSx33vxQC4kdPqJ3RugJ+od/bq7M90l7Wm/FGH0LmnOn/awusnDFOQCRG2S60bsqmlmJthvbPXtRaMuf8MLxzEbXvy7+AjG42tIqoEmOHzJexrfBS2NCPACWklTO9bwIDAQAB"),
    RSA_PRIVATE_1024("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJICxtNJUF+xtZ+SLWKinYsYIj7vRRZpehaHNxWhrOD+NuVLHfe/FALiR0+ondG6An6h39ursz3SXtab8UYfQuac6f9rC6ycMU5AJEbZLrRuyqaWYm2G9s9e1Foy5/wwvHMRte/Lv4CMbja0iqgSY4fMl7Gt8FLY0I8AJaSVM71vAgMBAAECgYB5tN7Ol7nrSlI+ZLZ4FVyE6OUC2KcZ+2nNBYChA1b7ZGuVzXt5W0ju7nbKq56Bhy81JvFWRlTuH0D2Wp5O+RflqCTAVTayWPqcwVLgBQNiuJ4bTaTaoVrpaeyEWhQhjxJLIHrasI/bnpPOMvSLnWDHCh8jXNcsZfuxVjpj3kw6gQJBAMmqqTr3eDrhgLXNdX36ASPRK0N3+Oh/Ta5rmA+AdGY7yqOJnXN6zANa1pzX/iag0ASuNWezx33uF5lQdky55zECQQC5WW1sH6Qe0Z9Vl7AVoJj+YPROGP99d+y82MlOMmitmTjnUAQWWWFL4EXfyZ1CUrIuawZjKrZLWDm4xKzm8gafAkARpCk7rExLMlDVFo0RoR4aaQDU3RjcFc7Q1D6wFHeaPd7DIZWxdWuFW5vsioSEEos/7ZFkafiojnxn//7pRVXxAkAmcjBKTz3hzqV4QaCau9dAXKgQUwsb4XZPrcAD4lzoNXIiOOzAHgYakQitZMqj6TdgfX6zrzZk5oYCl3kt5mINAkEAnuk9H2/mLGIIdsZb09FLnHlPljTOCKCM6es72XbELd9hiD/nzu58ho91CJnVK1BD8AlyS9jUqmgTxaSQ8SXqhg=="),
}

@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class EncryptRequest(val plainText: String? = null,
                               val plainKey: String? = null)

@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class EncryptResponse(val cipherText: String? = null,
                                val cipherKey: String? = null)


@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class DecryptRequest(val cipherText: String? = null,
                               val cipherKey: String? = null)

@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class DecryptResponse(val plainText: String? = null,
                                val plainKey: String? = null)


@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy::class)
data class GenerateKeyResponse(val plainKey: String? = null,
                               val rsaEncryptedKey: String? = null)