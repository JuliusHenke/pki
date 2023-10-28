package certificate

import org.bouncycastle.jce.provider.HybridCertPathValidatorSpi
import java.io.File
import java.security.cert.*
import java.util.*

val x509CertificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")

fun verifyCertificateChain(certificateFiles: List<String>): Boolean {
    val certificates: MutableList<X509Certificate> = LinkedList()
    certificateFiles.forEach { certificates.add(loadX509Certificate(it)) }

    val certificatePath: CertPath = x509CertificateFactory.generateCertPath(certificates)
    val anchors: MutableSet<TrustAnchor> = HashSet()
    anchors.add(TrustAnchor(certificates[certificates.size - 1], null))
    val params = PKIXParameters(anchors)
    params.isRevocationEnabled = false
    val validatorResult = HybridCertPathValidatorSpi().engineValidate(certificatePath, params)
    return validatorResult.isHybridChainValidated
}

fun loadX509Certificate(path: String): X509Certificate =
    x509CertificateFactory.generateCertificate(File(path).inputStream()) as X509Certificate