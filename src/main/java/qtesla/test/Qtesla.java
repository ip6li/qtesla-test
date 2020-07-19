package qtesla.test;


import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import java.security.*;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;



public final class Qtesla {
    private final AsymmetricCipherKeyPair asymmetricCipherKeyPair;

    private Qtesla() throws Exception {
        QTESLAKeyPairGenerator qteslaKeyPairGenerator = new QTESLAKeyPairGenerator();
        QTESLAKeyGenerationParameters qteslaKeyGenerationParameters = new QTESLAKeyGenerationParameters(
                QTESLASecurityCategory.PROVABLY_SECURE_III,
                SecureRandom.getInstance("NativePRNG")
        );
        qteslaKeyPairGenerator.init(qteslaKeyGenerationParameters);
        asymmetricCipherKeyPair = qteslaKeyPairGenerator.generateKeyPair();
    }


    public byte[] sign (byte[] messageToSign) {
        QTESLASigner qteslaSigner = new QTESLASigner();
        ParametersWithRandom parametersWithRandom = new ParametersWithRandom(asymmetricCipherKeyPair.getPrivate());
        qteslaSigner.init(true, parametersWithRandom);

        return qteslaSigner.generateSignature(messageToSign);
    }


    public boolean verify (byte[] messageToVerify, byte[] sig) {
        QTESLASigner qteslaSigner = new QTESLASigner();
        qteslaSigner.init(false, asymmetricCipherKeyPair.getPublic());

        return  qteslaSigner.verifySignature(messageToVerify, sig);
    }


    public static Qtesla getInstance() throws Exception {

        return new Qtesla();
    }

}
