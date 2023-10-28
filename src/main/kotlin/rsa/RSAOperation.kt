package rsa

import java.security.MessageDigest
import java.security.Signature
import javax.crypto.Cipher

val signatureAlgorithm: Signature = Signature.getInstance("SHA256withRSA")

fun hashSHA256(message: String): ByteArray {
    val sha256 = MessageDigest.getInstance("SHA-256")
    sha256.update(message.toByteArray())
    return sha256.digest()
}

fun encryptRSA(message: ByteArray, publicKeyResourceFileName: String): ByteArray {
    val encryptionEngine = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    val publicKey = getPublicRSAKeyFromFile(publicKeyResourceFileName)
    encryptionEngine.init(Cipher.ENCRYPT_MODE, publicKey)
    return encryptionEngine.doFinal(message)
}

fun signMessageRSA(message: ByteArray, privateKeyFile: String): ByteArray {
    signatureAlgorithm.initSign(getKeyPairRSAPKCS1FromFile(privateKeyFile).private)
    signatureAlgorithm.update(message)
    return signatureAlgorithm.sign()
}

fun verifySignatureRSA(signature: ByteArray, message: ByteArray, publicKeyFile: String): Boolean {
    signatureAlgorithm.initVerify(getPublicRSAKeyFromFile(publicKeyFile))
    signatureAlgorithm.update(message)
    return signatureAlgorithm.verify(signature)
}


