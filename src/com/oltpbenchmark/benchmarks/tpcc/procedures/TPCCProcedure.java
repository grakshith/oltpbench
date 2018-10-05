/******************************************************************************
 *  Copyright 2015 by OLTPBenchmark Project                                   *
 *                                                                            *
 *  Licensed under the Apache License, Version 2.0 (the "License");           *
 *  you may not use this file except in compliance with the License.          *
 *  You may obtain a copy of the License at                                   *
 *                                                                            *
 *    http://www.apache.org/licenses/LICENSE-2.0                              *
 *                                                                            *
 *  Unless required by applicable law or agreed to in writing, software       *
 *  distributed under the License is distributed on an "AS IS" BASIS,         *
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *  See the License for the specific language governing permissions and       *
 *  limitations under the License.                                            *
 ******************************************************************************/

package com.oltpbenchmark.benchmarks.tpcc.procedures;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Random;
import java.security.*;
import com.oltpbenchmark.api.Procedure;
import com.oltpbenchmark.benchmarks.tpcc.TPCCWorker;
import java.util.Base64;
import org.apache.log4j.Logger;
import java.nio.file.*;
import java.security.spec.*;

public abstract class TPCCProcedure extends Procedure {

    private static final Logger LOG = Logger.getLogger(TPCCWorker.class);
    public static final boolean debug = true;
    public PrivateKey priv;
    public PublicKey pub;
    public StringBuffer pub_key;
    
    public void read_file() throws Exception{
        try{

            byte[] privkeyBytes = Files.readAllBytes(Paths.get("/media/dsladmin/Linux/rakshith/pg_credereum/sample/pkcs8_key"));
            byte[] pubkeyBytes = Files.readAllBytes(Paths.get("/media/dsladmin/Linux/rakshith/pg_credereum/sample/public_key.der"));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privkeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            priv=kf.generatePrivate(spec);

            pub_key = new StringBuffer();
            pub_key.append("-----BEGIN PUBLIC KEY-----\n");
            pub_key.append("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt48z3qa689HS1XeCfpbL\n");
            pub_key.append("rX1C7yeNZle0QfeIuIMpqqXs+hTMRtZyZX5kO/cZ4uNk0aHKPgTHCamMOBTbQJyp\n");
            pub_key.append("rzOnvi2XhJQSc8rvCw1kKKp9TIDzYwn4z4eiUp++XQPdEr/WmPUwApRGVvV66sb6\n");
            pub_key.append("MogNHq0wE4WgiVZSaMhrfOijYRK+4NAGPVQhSL0pTAHxuRDVbH/AKi/xcefZqLXY\n");
            pub_key.append("QunMxy+BdhoZEkjYIfT/M+4KXE4nn6ZXnFjKEJz/GmmIwOvS2zpIhSy0pbYDWBUr\n");
            pub_key.append("6SF5An/LOM6B1N54mVFPVyCcGwrCoCsl+ItWa1tGAlB8K2Vq4oNIsX0l8cHXsS6I\n");
            pub_key.append("JQIDAQAB\n");
            pub_key.append("-----END PUBLIC KEY-----");

            // X509EncodedKeySpec pub_spec = new X509EncodedKeySpec(pubkeyBytes);
            // pub=kf.generatePublic(pub_spec);
            // LOG.debug("Public key is "+pub.toString());
            // KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
            // SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            // pub_key = new StringBuffer();
            // keyGen.initialize(2048, random);
            // KeyPair pair = keyGen.generateKeyPair();
            // priv = pair.getPrivate();
            // pub = pair.getPublic();
            // pub_key.append("-----BEGIN PUBLIC KEY-----\n");  
            // pub_key.append(Base64.getMimeEncoder().encodeToString( pub.getEncoded())+"\n");
            // pub_key.append("-----END PUBLIC KEY-----\n");
            // // LOG.info("Public Key is "+ pub_key.toString());
        }
        catch(Exception e){
            LOG.error("ERROR:",e);
        }
    }

    public abstract ResultSet run(Connection conn, Random gen,
            int terminalWarehouseID, int numWarehouses,
            int terminalDistrictLowerID, int terminalDistrictUpperID,
            TPCCWorker w) throws SQLException;

}
