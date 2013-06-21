package maps;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import com.sap.aii.mapping.api.AbstractTrace;
import com.sap.aii.mapping.api.AbstractTransformation;
import com.sap.aii.mapping.api.StreamTransformationConstants;
import com.sap.aii.mapping.api.StreamTransformationException;
import com.sap.aii.mapping.api.TransformationInput;
import com.sap.aii.mapping.api.TransformationOutput;

 
public class PGPEncryption extends AbstractTransformation {
      private Map param;
      private AbstractTrace trace;
 
      public void setParameter(Map param) {
            this.param = param;
      }
      
    public void transform(TransformationInput arg0, TransformationOutput arg1)
	throws StreamTransformationException {

		this.execute(arg0.getInputPayload().getInputStream(), arg1
				.getOutputPayload().getOutputStream());
	}
      
 
      public void execute(InputStream in, OutputStream out) throws StreamTransformationException {
            if (param instanceof java.util.Map) {
                  trace = (AbstractTrace) ((Map) param).get(StreamTransformationConstants.MAPPING_TRACE);
            }
            try {
//                  String publicKeyPath = "/publickey2.pkr";
                  
                  String publicKeyPath = "/vikaspublic.asc";                  
                  // Encrypt the message

                  new PGPCrypto().encrypt(publicKeyPath, in, out, trace);
            } catch (Exception e) {
                  e.printStackTrace();
            }
      }
 
      // for unit testing.
      public static void main(String[] args) throws Exception {
            try {
            	
    			InputStream in = new FileInputStream(new File("C:\\PGP\\keys2\\extract_TEST_payment_gl_p0030530l7ux.txt"));

    			OutputStream out = new FileOutputStream(new File("C://PGP//keys2//extract_TEST_payment_gl_p0030530l7ux.pgp"));            	
    			           	
                  new PGPEncryption().execute(in, out);
            } catch (Exception e) {
            }
      }
}
