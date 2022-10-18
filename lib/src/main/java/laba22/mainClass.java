package laba22;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class mainClass {

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate certificate = (X509Certificate) certFactory
				.generateCertificate(new FileInputStream("public.cer"));
		
		char[] keystorePassword = "password".toCharArray();
		char[] keyPassword = "password".toCharArray();
		
		KeyStore keystore = KeyStore.getInstance("PKCS12");
		keystore.load(new FileInputStream("private.p12"), keystorePassword);
		PrivateKey privateKey = (PrivateKey) keystore.getKey("baeldung", keyPassword);

		String secretMessage = "My password is 123456Seven";
		System.out.println("Original Message : " + secretMessage);
		byte[] stringToEncrypt = secretMessage.getBytes();
		byte[] encryptedData = encryptData(stringToEncrypt, certificate);
		System.out.println("Encrypted Message : " + new String(encryptedData));
		byte[] rawData = decryptData(encryptedData, privateKey);
		String decryptedMessage = new String(rawData);
		System.out.println("Decrypted Message : " + decryptedMessage);

		byte[] signedData = signData(rawData, certificate, privateKey);
		Boolean check = verifySignedData(signedData);
		System.out.println(check);

	}

	public static byte[] encryptData(byte[] data, X509Certificate encryptionCertificate)
			throws CertificateEncodingException, CMSException, IOException {
		byte[] encryptedData = null;
		if (null != data && null != encryptionCertificate) {

			CMSEnvelopedDataGenerator cmsEnvelopedDataGenerator = new CMSEnvelopedDataGenerator();
			JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
			cmsEnvelopedDataGenerator.addRecipientInfoGenerator(jceKey);
			CMSTypedData msg = new CMSProcessableByteArray(data);
			OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC")
					.build();
			CMSEnvelopedData cmsEnvelopedData = cmsEnvelopedDataGenerator.generate(msg, encryptor);
			encryptedData = cmsEnvelopedData.getEncoded();
		}
		return encryptedData;
	}

	public static byte[] decryptData(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException {
		byte[] decryptedData = null;
		if (null != encryptedData && null != decryptionKey) {
			CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
			Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
			KeyTransRecipientInformation recipientInfo = (KeyTransRecipientInformation) recipients.iterator().next();
			JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);
			return recipientInfo.getContent(recipient);
		}
		return decryptedData;
	}

	public static byte[] signData(byte[] data, X509Certificate signingCertificate, PrivateKey signingKey)
			throws Exception {
		byte[] signedMessage = null;
		List<X509Certificate> certList = new ArrayList<X509Certificate>();
		CMSTypedData cmsData = new CMSProcessableByteArray(data);
		certList.add(signingCertificate);
		Store certs = new JcaCertStore(certList);
		CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
		cmsGenerator.addSignerInfoGenerator(
				new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
						.build(contentSigner, signingCertificate));
		cmsGenerator.addCertificates(certs);
		CMSSignedData cms = cmsGenerator.generate(cmsData, true);
		signedMessage = cms.getEncoded();
		return signedMessage;
	}

	public static boolean verifySignedData(byte[] signedData) throws Exception {
		ByteArrayInputStream inputStream = new ByteArrayInputStream(signedData);
		ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
		CMSSignedData cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		SignerInformation signer = signers.getSigners().iterator().next();
		Collection<X509CertificateHolder> certCollection = cmsSignedData.getCertificates().getMatches(signer.getSID());
		X509CertificateHolder certHolder = certCollection.iterator().next();
		return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
	}

}
