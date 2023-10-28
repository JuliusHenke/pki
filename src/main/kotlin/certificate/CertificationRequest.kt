package certificate

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.HybridCertificateBuilder
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import org.bouncycastle.pkcs.HybridCSRBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pqc.crypto.qtesla.QTESLAContentSigner
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters
import org.bouncycastle.util.io.pem.PemReader
import java.io.File
import java.io.FileReader
import java.io.FileWriter
import java.math.BigInteger
import java.security.PublicKey
import java.security.cert.X509Certificate

fun createCertificationRequest(
    caPrimary: AsymmetricCipherKeyPair,
    caPrimaryPublic: PublicKey,
    caSecondary: AsymmetricCipherKeyPair,
    x500Name: X500Name,
): PKCS10CertificationRequest {
    val csrBuilder = HybridCSRBuilder(
        x500Name,
        caPrimaryPublic,
        caSecondary.public
    )

    val publicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(caPrimary.public)
    csrBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        SubjectKeyIdentifier(publicKeyInfo.getKeyIdentifier())
    )

    val sigAlg = DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA")
    val digAlg = DefaultDigestAlgorithmIdentifierFinder().find(sigAlg)
    val primarySigner = BcRSAContentSignerBuilder(sigAlg, digAlg).build(caPrimary.private)

    val secondarySigner = QTESLAContentSigner(caSecondary.private as QTESLAPrivateKeyParameters)

    return csrBuilder.buildHybrid(primarySigner, secondarySigner)
}

fun saveCertificationRequest(csr: PKCS10CertificationRequest, filename: String) {
    val writer = JcaPEMWriter(FileWriter(filename))
    writer.writeObject(csr)
    writer.close()
}

fun loadCertificationRequest(path: String): PKCS10CertificationRequest {
    val pemReader = PemReader(FileReader(File(path)))
    val pemObject = pemReader.readPemObject()
    return PKCS10CertificationRequest(pemObject.content)
}

fun createCACertForOpenCertificationRequest(
    issuer: X500Name,
    caPrimary: AsymmetricCipherKeyPair,
    caSecondary: AsymmetricCipherKeyPair,
    authorityCertificate: X509Certificate,
    x500NameAuthority: X500Name,
    certificationRequest: PKCS10CertificationRequest,
    csrSecondaryPublicKey: AsymmetricKeyParameter,
): X509Certificate {
    val certBuilder = HybridCertificateBuilder(
        issuer,
        BigInteger.valueOf(1),
        yesterdayUTC(),
        oneYearUTC(),
        certificationRequest.subject,
        certificationRequest.subjectPublicKeyInfo,
        csrSecondaryPublicKey,
    )
    certBuilder.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        AuthorityKeyIdentifier(
            authorityCertificate.getRSAKeyIdentifier(),
            GeneralNames(
                GeneralName(
                    GeneralName.directoryName,
                    x500NameAuthority
                )
            ),
            authorityCertificate.serialNumber
        )
    )
    certBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
    certBuilder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
    certBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        SubjectKeyIdentifier(certificationRequest.subjectPublicKeyInfo.getKeyIdentifier())
    )

    return buildHybridCertificate(
        certBuilder,
        caPrimary,
        caSecondary,
    )
}